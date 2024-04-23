//
// Created by User on 4/23/2024.
//

#ifndef NETWORK_BYTES_PROTOCOL_CLIENTTCP_H
#define NETWORK_BYTES_PROTOCOL_CLIENTTCP_H


#include "Client.h"

class ClientTCP: public Client{
public:
    explicit ClientTCP(const char *data, size_t data_size, sockaddr_in server_address, int port) :
            Client(TCP_PROTOCOL_ID, data, data_size, server_address, port) {}
protected:
    int create_connection_socket() override;
    void send_packet_to_server(void *packet, ssize_t packet_size) override;
    uint8_t receive_packet_from_server(const std::function<bool(int, void *)> &match_packet) override;
};


#endif //NETWORK_BYTES_PROTOCOL_CLIENTTCP_H
