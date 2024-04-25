#ifndef NETWORK_BYTES_PROTOCOL_SERVER_H
#define NETWORK_BYTES_PROTOCOL_SERVER_H

#include <cstdint>
#include <memory>
#include "protocol.h"
#include <string>
#include <functional>
#include <netinet/in.h>

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
    int port;
    struct Session {
        uint64_t session_id;
        int session_fd;
        uint64_t data_length;
        sockaddr_in client_address;
    } session{};
    char recv_buffer[MAX_PACKET_SIZE]{};
    int connection_fd = -1;
    virtual uint8_t receive_packet_from_all(std::function<bool(int type, void *buf)> match_packet) = 0;
    virtual uint8_t receive_packet_from_client(const std::function<bool(int, void *)> &match_packet) = 0;
    virtual void send_packet_to_client(void* packet, ssize_t packet_size) = 0;

    void _setup_socket_with(int socket_type);
};



#endif //NETWORK_BYTES_PROTOCOL_SERVER_H
