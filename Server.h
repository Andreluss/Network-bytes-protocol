//
// Created by User on 4/21/2024.
//

#ifndef NETWORK_BYTES_PROTOCOL_SERVER_H
#define NETWORK_BYTES_PROTOCOL_SERVER_H

#include <cstdint>
#include <memory>
#include "protocol.h"
#include <string>
#include <functional>

class Server {
public:
    virtual void run();
    explicit Server(int port): port(port) {}
protected:
    void new_session();
    virtual void setup_socket() = 0;
    virtual void ppcb_establish_connection() = 0;
    virtual void ppcb_receive_data() = 0;
    virtual void ppcb_end_connection() = 0;
    struct Session {
        uint64_t session_id;
        int session_fd;
        uint64_t data_length;
        sockaddr_in client_address;
    } session{};
    char recv_buffer[MAX_PACKET_SIZE]{};
    virtual uint8_t receive_packet(std::function<bool(int type, void *buf)> match_packet, bool from_everyone) = 0;
    virtual void send_packet(void* packet, size_t packet_size) = 0;
    int port;
    int connection_socket_fd;

    void _setup_socket_with(int socket_type);

    static void _set_socket_recv_timeout(int socket_fd, int timeout_seconds, int timeout_microseconds);
};



#endif //NETWORK_BYTES_PROTOCOL_SERVER_H
