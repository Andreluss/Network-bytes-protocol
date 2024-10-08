#include <stdexcept>
#include <csignal> // for SIGPIPE and SIG_IGN
#include "ClientTCP.h"

int ClientTCP::create_connection_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) syserr("creating tcp socket");

    // VERY IMPORTANT - this prevents the write() from crashing the server on broken PIPE error:
    signal(SIGPIPE, SIG_IGN);

    // set a timeout for connecting via tcp
    // Actually, the client may connect anyway (because of tcp connect mechanism),
    // but then it will time out on the first read/write operation.

    set_socket_recv_timeout(sock, MAX_WAIT, 0);

    debug("Connecting TCP socket to server... "); // fflush(stderr);
    if (connect(sock, (struct sockaddr *) &server_address, sizeof(server_address)) == -1)
        syserr("connect");
    debug("Connected!\n");

    return sock;
}

void ClientTCP::send_packet_to_server(void *packet, ssize_t packet_size) {
    assert(packet_size > 0);
    auto bytes_sent = writen(sock, packet, packet_size);
    if (bytes_sent != packet_size)
        throw std::runtime_error("send (packet " + std::to_string(*(uint8_t*)packet) + ") - partial / failed write: "
                                 " " + std::to_string(bytes_sent) + " of " + std::to_string(packet_size) + " bytes");
}

uint8_t ClientTCP::receive_packet_from_server(const std::function<bool(int, void *)> &match_packet) {
    int64_t microseconds_left = MAX_WAIT * 1000 * 1000;
    while (microseconds_left > 0) {
        set_socket_recv_timeout(sock, static_cast<int>(microseconds_left / 1000000),
                                static_cast<int>(microseconds_left % 1000000));
        microseconds_left -= measure_time_microseconds([&](){
            received_packet_size = read_packet_from_stream(sock, received_packet);
        });

        // 1. Was anything received?
        if (received_packet_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            else throw std::runtime_error("read - failed to receive packet");
        }

        // 2. Check if the packet is not corrupted and process it (or throw exception otherwise - it will crash the client)
        auto packet_type = validate_packet(received_packet, received_packet_size);

        if (match_packet(packet_type, received_packet)) {
            return packet_type;
        }
        else {
            debug("x-- skip %s filtered out\n", packet_short_info(packet_type, received_packet, false).c_str());
        }
    }
    throw ppcb_timeout_exception("Timeout ;_;");
}
