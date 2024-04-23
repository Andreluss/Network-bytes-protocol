//
// Created by User on 4/23/2024.
//

#include "ClientUDPR.h"

void ClientUDPR::send_packet_to_server(void *packet, ssize_t packet_size) {
    ClientUDP::send_packet_to_server(packet, packet_size);
    // save the last sent packet in case of retransmissions
    memcpy(sent_packet, packet, packet_size);
    sent_packet_size = packet_size;
    sent_packet_type = *(uint8_t*)packet;
}

uint8_t ClientUDPR::receive_packet_from_server(const std::function<bool(int, void *)> &match_packet) {
    uint8_t received_packet_type = -1;
    for (int retransmissions_left = retransmissions; ; retransmissions_left--) {
        try {
            received_packet_type = ClientUDP::receive_packet_from_server(match_packet);
            return received_packet_type; // successfully received the packet
        }
        catch (ppcb_timeout_exception& e) {
            if (retransmissions_left <= 0) { // no more retransmissions...
                throw e; // ...so the real timeout has happened
            }
            fprintf(stderr, "-r-> ret [packet %d] (attempt %d/%d)\n", sent_packet_type,
                    retransmissions - retransmissions_left + 1, retransmissions);
            send_packet_to_server(sent_packet, sent_packet_size);
        }
    }
}
