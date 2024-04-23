//
// Created by User on 4/23/2024.
//

#ifndef NETWORK_BYTES_PROTOCOL_CLIENTUDPR_H
#define NETWORK_BYTES_PROTOCOL_CLIENTUDPR_H

#include "ClientUDP.h"

class ClientUDPR : public ClientUDP {
public:
    explicit ClientUDPR(const char *data, size_t data_size, sockaddr_in server_address, int port) :
            ClientUDP(UDPR_PROTOCOL_ID, data, data_size, server_address, port, true) {}
protected:

    int retransmissions = MAX_RETRANSMITS;
    char sent_packet[MAX_PACKET_SIZE]{}; // buffer for the last sent packet
    uint8_t sent_packet_type = -1;
    void send_packet_to_server(void *packet, ssize_t packet_size) override;

    uint8_t receive_packet_from_server(const std::function<bool(int, void *)> &match_packet) override;

    ssize_t sent_packet_size;
};


#endif //NETWORK_BYTES_PROTOCOL_CLIENTUDPR_H
