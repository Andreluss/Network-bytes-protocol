#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cstdint>
#include <arpa/inet.h>
#include <sys/types.h>
#include <cassert>

#include "common.h"
#include "protocol.h"
#include "ClientUDP.h"
#include "ClientUDPR.h"
#include "ClientTCP.h"

// Returns a new socket connected to the server or -1 on error
int tcp_establish_connection(struct sockaddr_in *server_address) {
    // create a socket
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        syserr("socket");

    fprintf(stderr, "Trying to connect to the server... ");
    fflush(stderr);
    // connect to the server via TCP
    if (connect(sock, (struct sockaddr *) server_address, sizeof(*server_address)) == -1)
        syserr("connect");
    fprintf(stderr, "CONNECTED!\n");
    // configure the socket timeouts
    struct timeval tv = {
            .tv_sec = MAX_WAIT,
            .tv_usec = 0
    };
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        syserr("setsockopt");
    // if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
    //     syserr("setsockopt");

    return sock;
}

uint64_t tcp_start_protocol(int sock, size_t buf_size) {
    // generate the session id
    uint64_t session_id = random_64();

    // send the CONN packet
    fprintf(stderr, "Sending the CONN packet with data_length = %ld... \n", buf_size);
    conn_packet conn;
    conn_packet_init(&conn, session_id, TCP_PROTOCOL_ID, buf_size);
    fprintf(stderr, "Conn packet data_length: %" PRIu64 "\n", conn.data_length);
    if (writen(sock, &conn, sizeof(conn)) != sizeof(conn))
        syserr("write (conn)");

    // receive the CONACC packet
    conacc_packet conacc;
    if (readn(sock, &conacc, sizeof(conacc)) != sizeof(conacc))
        syserr("tcp-start: read (conacc)");
    if (conacc.type != CONACC_PACKET_TYPE)
        fatal("tcp-start: unexpected packet type: %d", conacc.type);
    if (conacc.session_id != session_id)
        fatal("tcp-start: unexpected session id: %d", conacc.session_id);

    return session_id;
}

void tcp_send_data_packet(int sock, uint64_t session_id, uint64_t packet_number, size_t data_size, char* data) {
    static data_packet_t data_packet; // static for performance reasons
    int packet_size = DATA_PACKET_HEADER_LENGTH + data_size;
    data_packet_init(&data_packet, session_id, packet_number, data_size, data);

    if (writen(sock, &data_packet, packet_size) != packet_size) {
        syserr("write (while sending the data packet)");
    }
}

void tcp_send_data_packets(int sock, uint64_t session_id, char* buf, size_t buf_size) {
    char* data_ptr = buf;
    size_t bytes_left = buf_size;
    uint64_t packet_number = 0;
    while (bytes_left > 0) {
        size_t data_size = bytes_left >= DATA_PACKET_DATA_LENGTH ? DATA_PACKET_DATA_LENGTH : bytes_left;

        assert(DATA_PACKET_DATA_LENGTH <= DATA_PACKET_MAX_DATA_LENGTH);
        fprintf(stderr, "--> Trying to send packet #%ld with data size %ld (total size: %ld)... ",
                        packet_number, data_size, DATA_PACKET_HEADER_LENGTH + data_size);

        tcp_send_data_packet(sock, session_id, packet_number, data_size, data_ptr);
        
        fprintf(stderr, "OK\n");

        bytes_left -= data_size;
        data_ptr += data_size;
        packet_number++;
    }
    fprintf(stderr, "Sent %" PRIu64 " data packets. \n", packet_number);
}

void tcp_receive_rcvd_packet(int sock, uint64_t id) {
    rcvd_packet rcvd;
    if (readn(sock, &rcvd, sizeof(rcvd)) != sizeof(rcvd))
        syserr("read (rcvd)");
    if (rcvd.type != RCVD_PACKET_TYPE)
        fatal("unexpected packet type: %d", rcvd.type);
    if (rcvd.session_id != id)
        fatal("unexpected session id: %d", rcvd.session_id);
}

// keep in mind the protocol.h file
void tcp(struct sockaddr_in *server_address, char *buf, size_t buf_size) {
    // establish a TCP connection
    int sock = tcp_establish_connection(server_address);

    // -------------- start the protocol --------------

    uint64_t session_id = tcp_start_protocol(sock, buf_size);

    // -------------- send the data --------------

    tcp_send_data_packets(sock, session_id, buf, buf_size);

    // -------------- end the protocol --------------

    tcp_receive_rcvd_packet(sock, session_id);

    // close the connection
    if (close(sock) == -1)
        syserr("close");
}

// Function that reads all data from stdin until EOF or error and saves it in a dynamically (re)allocated buffer.
char* read_data(size_t *buf_size) {
    size_t buf_capacity = 1024;
    char* buf = (char*)malloc(buf_capacity);
    if (buf == NULL)
        syserr("malloc");

    size_t bytes_read = 0;
    while (true) {
        if (bytes_read == buf_capacity) {
            buf_capacity *= 2;
            buf = (char*)realloc(buf, buf_capacity);
            if (buf == NULL)
                syserr("realloc");
        }

        ssize_t bytes = read(STDIN_FILENO, buf + bytes_read, buf_capacity - bytes_read);
        if (bytes == -1)
            syserr("read");
        if (bytes == 0) {
            *buf_size = bytes_read;
            return buf;
        }
        bytes_read += bytes;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fatal("usage: %s <tcp / udp / udpr> <host> <port>", argv[0]);
    }

    // read the protocol, host and port
    const char *protocol = argv[1];
    std::vector<std::string> valid_protocols = {"tcp", "udp", "udpr", "fidelio"};
    if (std::find(valid_protocols.begin(), valid_protocols.end(), protocol) == valid_protocols.end())
        fatal("unknown protocol: %s", protocol);
    const char *host = argv[2];
    uint16_t port = read_port(argv[3]);
    struct sockaddr_in server_address = get_server_address(host, port);

    fprintf(stderr, "Reading data: \n");
    size_t buf_size;
    char* buf = read_data(&buf_size);
    if (buf_size == 0)
        fatal("empty input");
    fprintf(stderr, "Read %" PRIu64 " bytes from stdin.\n", buf_size);
    fprintf(stderr, "Client config -> [%s:%d via %s]\n", host, port, protocol);
    fprintf(stderr, "-----------------------------------------------------\n");

    // start the connection using the selected protocol
    if (strcmp(protocol, "tcp") == 0) {
        ClientTCP(buf, buf_size, server_address, port).run();
    } else if (strcmp(protocol, "udp") == 0) {
        ClientUDP(buf, buf_size, server_address, port).run();
    } else if (strcmp(protocol, "udpr") == 0) {
        ClientUDPR(buf, buf_size, server_address, port).run();
    }

    free(buf);
    return 0;
}
