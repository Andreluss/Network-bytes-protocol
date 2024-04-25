#include <cinttypes>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <endian.h>
#include <cassert>

#include "common.h"
#include "protocol.h"
#include "ServerUDP.h"


// functions for server side reading the packets (they convert the packets to host byte order and chck the errors automatically)
int validate_conn_packet(conn_packet *conn, int is_tcp) {
    if (conn->type != CONN_PACKET_TYPE) {
        error("invalid packet type: %d, expected: %d", conn->type, CONN_PACKET_TYPE);
        return -1;
    }
    if (is_tcp) {
        if (conn->protocol_id != TCP_PROTOCOL_ID) {
            error("invalid protocol id: %d, expected: %d", conn->protocol_id, TCP_PROTOCOL_ID);
            return -1;
        }
    }
    else { // udp
        if (conn->protocol_id != UDP_PROTOCOL_ID && conn->protocol_id != UDPR_PROTOCOL_ID) {
            error("invalid protocol id: %d, expected udp(r)", conn->protocol_id);
            return -1;
        }
    }
    conn->data_length = be64toh(conn->data_length);
    if (conn->data_length < 1) {
        error("conn: invalid data length: %" PRIu64, conn->data_length);
        return -1;
    }
    return 0;
}

int tcp_read_conn(int fd, conn_packet *conn) {
    if (readn(fd, conn, sizeof(*conn)) != sizeof(*conn)) {
        error("readn: conn");
        return -1;
    }
    return validate_conn_packet(conn, 1);
}

// Returns a new socket connected to the server or -1 on error
int tcp_establish_connection(int socket_fd) {
    fprintf(stderr, "<*> ");
    struct sockaddr_in client_address{};
    socklen_t address_length = sizeof(client_address);
    int client_fd = accept(socket_fd, (struct sockaddr *) &client_address, &address_length);
    if (client_fd < 0) {
        error("accept");
        return -1;
    }
    fprintf(stderr, "%s:%d\n", inet_ntoa(client_address.sin_addr),
            ntohs(client_address.sin_port));

    struct timeval tv = {
            .tv_sec = MAX_WAIT,
            .tv_usec = 0
    };
    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        syserr("setsockopt");
    }
    return client_fd;
}

int validate_data_packet(data_packet_t* data_packet, uint64_t session_id) {
    if (data_packet->session_id != session_id) {
        error("invalid session id: %" PRIu64 ", expected: %" PRIu64, data_packet->session_id, session_id);
        return -1;
    }
    return 0;
}

int tcp_read_data_packet(int fd, data_packet_t *data, uint64_t session_id) {
    if (readn(fd, data, DATA_PACKET_HEADER_LENGTH) != DATA_PACKET_HEADER_LENGTH) {
        error("readn: data packet (header part)");
        return -1;
    }
    if (data->type != DATA_PACKET_TYPE) {
        error("invalid packet type: %d, expected: %d", data->type, DATA_PACKET_TYPE);
        return -1;
    }
    data->session_id = data->session_id;
    data->packet_number = be64toh(data->packet_number);
    data->data_length = be32toh(data->data_length);
    if (data->data_length < 1 || data->data_length > DATA_PACKET_MAX_DATA_LENGTH) {
        error("data: invalid data length: %" PRIu32, data->data_length);
        return -1;
    }
    // print the pointers compared in the assertion below
    assert((void*)&data->data == ((char*)data + DATA_PACKET_HEADER_LENGTH));
    if (readn(fd, data->data, data->data_length) != data->data_length) {
        error("readn: data packet (data part)");
        return -1;
    }
    if (validate_data_packet(data, session_id) < 0) {
        return -1;
    }
    return 0;
}

int tcp_write_rjt(int fd, uint64_t session_id, uint64_t packet_number) {
    rjt_packet rjt;
    rjt_packet_init(&rjt, session_id, packet_number);
    if (writen(fd, &rjt, sizeof(rjt)) != sizeof(rjt)) {
        error("writen: rjt");
        return -1;
    }
    return 0;
}

int tcp_write_rcvd(int fd, uint64_t session_id) {
    fprintf(stderr, "--> RCVD \n");
    rcvd_packet rcvd;
    rcvd_packet_init(&rcvd, session_id);
    if (writen(fd, &rcvd, sizeof(rcvd)) != sizeof(rcvd)) {
        error("writen: rcvd");
        return -1;
    }
    return 0;
}


int tcp_start_protocol(int fd, uint64_t* session_id, uint64_t* data_length) {
    // Read and check CONN packet.
    conn_packet conn;
    if (tcp_read_conn(fd, &conn) < 0) {
        return -1;
    }

    // Save the information from the CONN packet.
    *session_id = conn.session_id;
    *data_length = conn.data_length;

    // Send CONACC packet.
    conacc_packet conacc;
    conacc_packet_init(&conacc, conn.session_id);
    if (writen(fd, &conacc, sizeof(conacc)) != sizeof(conacc)) {
        error("writen: conacc");
        return -1;
    }
    return 0;
}

int tcp_read_data_packets(int fd, uint64_t session_id, uint64_t data_length) {
    static data_packet_t data_packet;
    // Read DATA packets.
    for (uint64_t next_packet_number = 0, bytes_received = 0; bytes_received < data_length; next_packet_number++) {
        // In TCP case, the packet is *always* from the client (no need to check the source).
        if (tcp_read_data_packet(fd, &data_packet, session_id) < 0) {
//            error("error while reading the data packet %d, connection rejected", next_packet_number);
            tcp_write_rjt(fd, session_id, next_packet_number);
            return -1;
        }
        if (data_packet.packet_number != next_packet_number) {
            error("invalid packet number: %" PRIu64 ", expected: %" PRIu64, data_packet.packet_number, next_packet_number);
            tcp_write_rjt(fd, session_id, next_packet_number);
            return -1;
        }
        // Print the data.
        if (print_data_packet(&data_packet, "\n") < 0) {
            return -1;
        }
        bytes_received += data_packet.data_length;
    }
    return 0;
}

int tcp_handle_new_client(int listening_socket_fd) {
    // Establish a TCP connection.
    int fd = tcp_establish_connection(listening_socket_fd);
    if (fd < 0) { return -1; }

    // -------------- start the protocol --------------
    uint64_t session_id; uint64_t data_length;
    if (tcp_start_protocol(fd, &session_id, &data_length) < 0) {
        close(fd);
        return -1;
    }

    // -------------- read the data --------------
    if (tcp_read_data_packets(fd, session_id, data_length) < 0) {
        close(fd);
        return -1;
    }

    // -------------- end the protocol --------------
    if (tcp_write_rcvd(fd, session_id) < 0) {
        close(fd);
        return -1;
    }
    // Close the connection.
    fprintf(stderr, "<x> \n");
    if (close(fd) < 0) {
        syserr("close");
    }

    return 0;
}

void sigint_handler(int signum) {
    fprintf(stderr, " SIGINT received(%d). Closing the connection... \n", signum);
    exit(0);
}

[[noreturn]] void tcp(uint16_t port) {
    // Create a socket.
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        syserr("cannot create a socket");
    }

    // VERY IMPORTANT - this prevents the write() from crashing the server on broken PIPE error:
    signal(SIGPIPE, SIG_IGN);

    // ------------------ warning ---------------------------
    // Enable address reuse.
    int optval = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        syserr("setsockopt");
    }
    // ------------------ warning ---------------------------

    // Bind the socket to a concrete address.
    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces.
    server_address.sin_port = htons(port);
    if (bind(socket_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        syserr("bind");
    }

    // Start listening on the socket.
    if (listen(socket_fd, INT_MAX) < 0) {
        syserr("listen");
    }

    while(true) {
        printf("--------------------------------\n");
        tcp_handle_new_client(socket_fd);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fatal("usage: %s <tcp/udp> <port>", argv[0]);
    }
    const char *protocol = argv[1];
    if (strcmp(protocol, "tcp") != 0 && strcmp(protocol, "udp") != 0)
        fatal("unknown server protocol: %s", protocol);
    uint16_t port = read_port(argv[2]);

    install_signal_handler(SIGINT, sigint_handler);

    if (strcmp(protocol, "tcp") == 0) {
        tcp(port);
    } else if (strcmp(protocol, "udp") == 0) {
        ServerUDP(port).run();
    }
}