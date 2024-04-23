//
// Created by User on 4/23/2024.
//

#ifndef NETWORK_BYTES_PROTOCOL_CLIENT_H
#define NETWORK_BYTES_PROTOCOL_CLIENT_H

#include <netinet/in.h>
#include <functional>
#include "protocol.h"

class Client {
public:
    virtual void run();
    explicit Client(uint8_t protocol_id, const char *data, size_t data_size, sockaddr_in server_address, int port,
                    bool data_ack = false) :
            data_to_send(data), data_to_send_size(data_size),
            c_data_ack(data_ack), c_protocol_id(protocol_id),
            server_address(server_address), port(port) {}
protected:
    const char* data_to_send;
    const size_t data_to_send_size;
    const bool c_data_ack; // if the client should wait for the ACC packet after each DATA packet
    const uint8_t c_protocol_id;
    const sockaddr_in server_address;
    const int port;

    virtual int create_connection_socket() = 0;
    int sock = -1;

    uint64_t session_id = 0xdeadbeef;
    void ppcb_establish_connection();
    void ppcb_send_data();
    void ppcb_end_connection();

    virtual void send_packet_to_server(void* packet, ssize_t packet_size) = 0;
    // The function receives a packet from the server and checks if it matches the match_packet function.
    // Note: the function should store the received packet in received_packet buffer.
    virtual uint8_t receive_packet_from_server(const std::function<bool(int, void *)> &match_packet) = 0;
    char received_packet[MAX_PACKET_SIZE]{}; // buffer for the received packet
    ssize_t received_packet_size = 0; // size of the received packet

private:
    void ppcb_get_ack(uint64_t packet_number);
};


#endif //NETWORK_BYTES_PROTOCOL_CLIENT_H
