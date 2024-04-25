#ifndef NETWORK_BYTES_PROTOCOL_CLIENTUDP_H
#define NETWORK_BYTES_PROTOCOL_CLIENTUDP_H

#include "Client.h"

class ClientUDP : public Client {
public:
    explicit ClientUDP(const char *data, size_t data_size, sockaddr_in server_address, int port) :
            Client(UDP_PROTOCOL_ID, data, data_size, server_address, port) {}
protected:
    int create_connection_socket() override;
    void send_packet_to_server(void* packet, ssize_t packet_size) override;
    // This function receives a packet matching the match_packet function from the server,
    // or throws ppcb_timeout_exception (timeout) or ppcb_invalid_packet_exception (corrupted/invalid packet).
    uint8_t receive_packet_from_server(const std::function<bool(int, void *)> &match_packet) override;

    explicit ClientUDP(uint8_t protocol_id, const char* data, size_t data_size, sockaddr_in server_address, int port, bool data_ack) :
            Client(protocol_id, data, data_size, server_address, port, data_ack) {}
};


#endif //NETWORK_BYTES_PROTOCOL_CLIENTUDP_H
