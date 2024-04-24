//
// Created by User on 4/23/2024.
//

#include "ClientUDP.h"
#include <arpa/inet.h>
#include <stdexcept>

int ClientUDP::create_connection_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) syserr("socket");
    return sock;
}

void ClientUDP::send_packet_to_server(void *packet, ssize_t packet_size) {
    assert(packet_size > 0);
    auto bytes_sent = sendto(sock, packet, packet_size, 0, (struct sockaddr *) &server_address, sizeof(server_address));
    if (bytes_sent != packet_size)
        throw std::runtime_error("sendto (packet " + std::to_string(*(uint8_t*)packet) + ") - partial / failed write: "
                                 " " + std::to_string(bytes_sent) + " of " + std::to_string(packet_size) + " bytes");
}

uint8_t ClientUDP::receive_packet_from_server(const std::function<bool(int, void *)> &match_packet) {
    int64_t microseconds_left = MAX_WAIT * 1000 * 1000;
    sockaddr_in received_packet_address{}; socklen_t received_packet_address_len = sizeof(received_packet_address);
    while (microseconds_left > 0) {
        set_socket_recv_timeout(sock, static_cast<int>(microseconds_left / 1000000),
                                      static_cast<int>(microseconds_left % 1000000));
        microseconds_left -= measure_time_microseconds([&](){
            received_packet_size = recvfrom(sock, received_packet, MAX_PACKET_SIZE, 0,
                                            (struct sockaddr *) &received_packet_address, &received_packet_address_len);
        });

        // 1. Was anything received?
        if (received_packet_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            else throw std::runtime_error("recvfrom - failed to receive packet");
        }

        // 2. Was server the packet sender?
        if (!sockaddr_in_equal(server_address, received_packet_address)) {
            fprintf(stderr, "<-- [packet %d] from unknown sender: %s:%d\n",
                    received_packet_size > 0 ? *(uint8_t*)received_packet : -1,
                    inet_ntoa(received_packet_address.sin_addr), ntohs(received_packet_address.sin_port));
            continue;
        }

        // 3. Check if the packet is not corrupted and process it (or throw exception otherwise - it will crash the client)
        auto packet_type = validate_packet(received_packet, received_packet_size);

        if (match_packet(packet_type, received_packet)) {
            return packet_type;
        }
        else {
            fprintf(stderr, "x-- skip %s filtered out\n", packet_short_info(packet_type, received_packet, false).c_str());
        }
    }
    throw ppcb_timeout_exception("Timeout ;_;");
}
