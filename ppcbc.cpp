#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cstdint>
#include <arpa/inet.h>
#include <sys/types.h>
#include <endian.h>
#include <cassert>
#include <cerrno>
#include <memory>

#include "common.h"
#include "protocol.h"
#include "ClientUDP.h"
#include "ClientUDPR.h"

// Returns a new socket connected to the server or -1 on error
int tcp_establish_connection(struct sockaddr_in *server_address) {
    // create a socket
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        syserr("socket");

    fprintf(stderr, "Trying to connect to the server... \n");
    // connect to the server via TCP
    if (connect(sock, (struct sockaddr *) server_address, sizeof(*server_address)) == -1)
        syserr("connect");

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

ssize_t udp_sendto(int fd, const void* buf, size_t n, const struct sockaddr_in *server_address) {
    return sendto(fd, buf, n, 0, (struct sockaddr*) server_address, (socklen_t) sizeof(*server_address));
}

char udp_recv_buffer[MAX_PACKET_SIZE];
// Returns the packet type if the buffer has the correct data. Otherwise, exits the program.
int get_packet_from_buffer(size_t buf_size) {
    uint8_t packet_type = *(uint8_t*)udp_recv_buffer;
    // Go through all packet types that the *client* could receive.
    acc_packet* acc;
    rjt_packet* rjt;
    switch (packet_type) {
        case CONACC_PACKET_TYPE:
            // Validate the conacc packet.
            if (buf_size != sizeof(conacc_packet))
                fatal("get_packet_from_buffer: invalid CONACC packet length: %zu, expected: %zu", buf_size, sizeof(conacc_packet));
            return CONACC_PACKET_TYPE;
        case CONRJT_PACKET_TYPE:
            // Validate the conrjt packet.
            if (buf_size != sizeof(conrjt_packet))
                fatal("get_packet_from_buffer: invalid CONRJT packet length: %zu, expected: %zu", buf_size, sizeof(conrjt_packet));
            return CONRJT_PACKET_TYPE;
        case ACC_PACKET_TYPE:
            // Validate the acc packet.
            if (buf_size != sizeof(acc_packet))
                fatal("get_packet_from_buffer: invalid ACC packet length: %zu, expected: %zu", buf_size, sizeof(acc_packet));
            // Convert the bytes order where needed.
            acc = (acc_packet*)udp_recv_buffer;
            acc->packet_number = be64toh(acc->packet_number);
            return ACC_PACKET_TYPE;
        case RJT_PACKET_TYPE:
            // Validate the rjt packet.
            if (buf_size != sizeof(rjt_packet))
                fatal("get_packet_from_buffer: invalid RJT packet length: %zu, expected: %zu", buf_size, sizeof(rjt_packet));
            // Convert the bytes order where needed.
            rjt = (rjt_packet*)udp_recv_buffer;
            rjt->packet_number = be64toh(rjt->packet_number);
            return RJT_PACKET_TYPE;
        case RCVD_PACKET_TYPE:
            // Validate the rcvd packet.
            if (buf_size != sizeof(rcvd_packet))
                fatal("get_packet_from_buffer: invalid RCVD packet length: %zu, expected: %zu", buf_size, sizeof(rcvd_packet));
            return RCVD_PACKET_TYPE;
        default:
            fatal("get_packet_from_buffer: unexpected packet type: %d", packet_type);
    }
}
// Returns the packet type if the buffer has the correct data.
int udp_packet_recvfrom(int fd, struct sockaddr_in *server_address) {
    socklen_t address_length = (socklen_t) sizeof(*server_address);
    ssize_t bytes_read = recvfrom(fd, udp_recv_buffer, MAX_PACKET_SIZE, 0, (struct sockaddr*) server_address, &address_length);
    if (bytes_read <= 0) {
        syserr("recvfrom");
    }

    return get_packet_from_buffer(bytes_read);
}

uint64_t udp_start_protocol(int fd, struct sockaddr_in* server_address, size_t buf_size) {
    // generate the session id
    uint64_t session_id = random_64();

    // send the CONN packet
    conn_packet conn;
    conn_packet_init(&conn, session_id, UDP_PROTOCOL_ID, buf_size);
    if (udp_sendto(fd, &conn, sizeof(conn), server_address) != sizeof(conn))
        syserr("udp_start_protocol: sendto (conn)");

    // receive the CONACC packet (or any other packet - CONNRJT for example)
    int type = udp_packet_recvfrom(fd, server_address);
    if (type == CONRJT_PACKET_TYPE) {
        fatal("udp_start_protocol: connection rejected"); // CHECK
    }
    else if(type != CONACC_PACKET_TYPE) {
        fatal("udp_start_protocol: unexpected packet type: %d", type);
    }

    conacc_packet* conacc = (conacc_packet*)udp_recv_buffer;
    if (conacc->session_id != session_id)
        fatal("udp_start_protocol: unexpected session id: %d in CONACC", conacc->session_id);

    return session_id;
}

void udp_send_data_packet(int sock, struct sockaddr_in* server_address, uint64_t session_id, uint64_t packet_number, size_t data_size, char* data) {
    static data_packet_t data_packet; // static for performance reasons
    int packet_size = DATA_PACKET_HEADER_LENGTH + data_size;
    data_packet_init(&data_packet, session_id, packet_number, data_size, data);

    if (udp_sendto(sock, &data_packet, packet_size, server_address) != packet_size) {
        syserr("write (while sending the data packet)");
    }
}

void udp_send_data_packets(int fd, struct sockaddr_in *server_address, uint64_t session_id, char *buf, size_t buf_size) {
    char* data_ptr = buf;
    size_t bytes_left = buf_size;
    uint64_t packet_number = 0;
    while (bytes_left > 0) {
        size_t data_size = bytes_left >= DATA_PACKET_DATA_LENGTH ? DATA_PACKET_DATA_LENGTH : bytes_left;

        assert(DATA_PACKET_DATA_LENGTH <= DATA_PACKET_MAX_DATA_LENGTH);
        fprintf(stderr, "--> Trying to send packet #%ld with data size %ld (total size: %ld)... ",
                packet_number, data_size, DATA_PACKET_HEADER_LENGTH + data_size);

        udp_send_data_packet(fd, server_address, session_id, packet_number, data_size, data_ptr);

        fprintf(stderr, "OK\n");

        bytes_left -= data_size;
        data_ptr += data_size;
        packet_number++;
    }
    fprintf(stderr, "Sent %" PRIu64 " data packets. \n", packet_number);
}

void udp_receive_rcvd_packet(int sock, struct sockaddr_in* server_address, uint64_t session_id) {
    int type = udp_packet_recvfrom(sock, server_address);
    if (type != RCVD_PACKET_TYPE) {
        fatal("unexpected packet type: %d (expected %d - RCVD)", type, RCVD_PACKET_TYPE);
    }

    rcvd_packet* rcvd = (rcvd_packet*)udp_recv_buffer;
    if (rcvd->session_id != session_id)
        fatal("unexpected session id: %d (expected %d)", rcvd->session_id, session_id);

    fprintf(stderr, "<-- RCVD \n");
}

int udp_setup_connection() {
    // create a socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        syserr("socket");

    // configure the socket timeouts
    struct timeval tv = {
        .tv_sec = MAX_WAIT,
        .tv_usec = 0
    };
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        syserr("setsockopt");

    return sock;
}

void udp(struct sockaddr_in *server_address, char *buf, size_t buf_size) {
    // Set up the UDP connection.
    int sock = udp_setup_connection();

    // -------------- start the protocol --------------
    uint64_t session_id = udp_start_protocol(sock, server_address, buf_size);

    // -------------- send the data --------------
    udp_send_data_packets(sock, server_address, session_id, buf, buf_size);

    // -------------- end the protocol --------------
    udp_receive_rcvd_packet(sock, server_address, session_id);

    // Close the connection.
    if (close(sock) == -1)
        syserr("close");
}

// Retransmission UDP recvfrom wrapper, takes last sent packet as an argument (to retransmit it if needed)
// and returns the packet type if the buffer has the correct data.
int updr_packet_recvfrom(int fd, struct sockaddr_in *server_address, void* last_sent_packet, ssize_t last_sent_packet_size) {
    for (int retransmission_count = 0; retransmission_count < MAX_RETRANSMITS; retransmission_count++) {
        socklen_t address_length = (socklen_t) sizeof(*server_address);
        ssize_t bytes_read = recvfrom(fd, udp_recv_buffer, MAX_PACKET_SIZE, 0, (struct sockaddr *) server_address,
                                      &address_length);
        // TODO check if the received packet came from totally different server
        // Check if there's a timeout or an error
        if (bytes_read == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "Timeout reached. Retransmitting the last packet... \n");
                if (udp_sendto(fd, last_sent_packet, last_sent_packet_size, server_address) != last_sent_packet_size)
                    syserr("updr_packet_recvfrom: sendto (retransmission)");
                continue;
            }
            syserr("recvfrom");
        }
        return get_packet_from_buffer(bytes_read);
    }
    fatal("updr_packet_recvfrom: maximum retransmissions reached");
}

int udpr_setup_connection() {
    return udp_setup_connection();
}

uint64_t updr_start_protocol(int fd, struct sockaddr_in* server_address, size_t buf_size) {
    // generate the session id
    uint64_t session_id = random_64();

    // send the CONN packet
    conn_packet conn;
    conn_packet_init(&conn, session_id, UDPR_PROTOCOL_ID, buf_size);
    fprintf(stderr, "--> CONN \n");
    if (udp_sendto(fd, &conn, sizeof(conn), server_address) != sizeof(conn)) {
        syserr("updr_start_protocol: sendto (conn)");
    }
    int type = updr_packet_recvfrom(fd, server_address, &conn, sizeof(conn));
    if (type == CONRJT_PACKET_TYPE) {
        fatal("updr_start_protocol: connection rejected");
    }
    else if (type != CONACC_PACKET_TYPE) {
        fatal("updr_start_protocol: unexpected packet type: %d, expected: %d", type, CONACC_PACKET_TYPE);
    }
    fprintf(stderr, "<-- CONACC \n");

    conacc_packet* conacc = (conacc_packet*)udp_recv_buffer;
    if (conacc->session_id != session_id) {
        fatal("updr_start_protocol: unexpected session id: %d in CONACC, expected: %d", conacc->session_id, session_id);
    }

    return session_id;
}

void udpr_send_data_packet(int sock, struct sockaddr_in* server_address, uint64_t session_id, uint64_t packet_number, size_t data_size, char* data, data_packet_t* data_packet) {
//    static data_packet_t data_packet_t; // static for performance reasons
    int packet_size = DATA_PACKET_HEADER_LENGTH + data_size;
    data_packet_init(data_packet, session_id, packet_number, data_size, data);

    fprintf(stderr, "--> DATA #%ld ", packet_number); fflush(stderr);
    if (udp_sendto(sock, data_packet, packet_size, server_address) != packet_size) {
        syserr("write (while sending the data packet)");
    }
    fprintf(stderr, "OK\n");

    int type = updr_packet_recvfrom(sock, server_address, data_packet, packet_size);
    if (type == RJT_PACKET_TYPE) {
        fatal("udpr_send_data_packet: packet rejected - closing the connection!");
    }
    else if (type != ACC_PACKET_TYPE) {
        fatal("udpr_send_data_packet: unexpected packet type: %d, expected: %d", type, ACC_PACKET_TYPE);
    }
    acc_packet* acc = (acc_packet*)udp_recv_buffer;
    if (acc->session_id != session_id) {
        fatal("udpr_send_data_packet: unexpected session id: %d in ACC, expected: %d", acc->session_id, session_id);
    }
    if (acc->packet_number != packet_number) {
        fatal("udpr_send_data_packet: unexpected packet number: %d in ACC, expected: %d", acc->packet_number, packet_number);
    }

    fprintf(stderr, "<-- ACC [%ld] \n", packet_number);
}

void udpr_receive_acc_packet(int sock, struct sockaddr_in* server_address, uint64_t session_id, uint64_t packet_number) {
    int type = updr_packet_recvfrom(sock, server_address, NULL, 0);
    if (type == RJT_PACKET_TYPE) {
        fatal("udpr_receive_acc_packet: packet rejected - closing the connection!");
    }
    else if (type != ACC_PACKET_TYPE) {
        fatal("udpr_receive_acc_packet: unexpected packet type: %d, expected: %d", type, ACC_PACKET_TYPE);
    }

    acc_packet* acc = (acc_packet*)udp_recv_buffer;
    if (acc->session_id != session_id) {
        fatal("udpr_receive_acc_packet: unexpected session id: %d in ACC, expected: %d", acc->session_id, session_id);
    }
    if (acc->packet_number != packet_number) {
        fatal("udpr_receive_acc_packet: unexpected packet number: %d in ACC, expected: %d", acc->packet_number, packet_number);
    }

    fprintf(stderr, "<-- ACC [%ld] \n", packet_number);
}


void udpr_send_data_packets(int fd, struct sockaddr_in *server_address, uint64_t session_id, char *buf, size_t buf_size, data_packet_t* last_data_packet) {
    char* data_ptr = buf;
    size_t bytes_left = buf_size;
    uint64_t packet_number = 0;
    while (bytes_left > 0) {
        size_t data_size = bytes_left >= DATA_PACKET_DATA_LENGTH ? DATA_PACKET_DATA_LENGTH : bytes_left;

        assert(DATA_PACKET_DATA_LENGTH <= DATA_PACKET_MAX_DATA_LENGTH);
        fprintf(stderr, "--> DATA #%ld with data size %ld (total size: %ld)... ",
                packet_number, data_size, DATA_PACKET_HEADER_LENGTH + data_size);

        udpr_send_data_packet(fd, server_address, session_id, packet_number, data_size, data_ptr, last_data_packet);

        // todo-test: remove after testing, this is a case of double acc
//        fprintf(stderr, "<-? ");
//        udpr_receive_acc_packet(fd, server_address, session_id, packet_number);

        bytes_left -= data_size;
        data_ptr += data_size;
        packet_number++;
    }
    fprintf(stderr, "Sent %" PRIu64 " data packets. \n", packet_number);
}

void udpr_receive_rcvd_packet(int sock, struct sockaddr_in* server_address, uint64_t session_id, void* last_sent_packet, size_t last_sent_packet_size) {
    int type = updr_packet_recvfrom(sock, server_address, last_sent_packet, last_sent_packet_size);
    if (type != RCVD_PACKET_TYPE) {
        fatal("unexpected packet type: %d, expected: %d", type, RCVD_PACKET_TYPE);
    }
    rcvd_packet *rcvd = (rcvd_packet *) udp_recv_buffer;
    if (rcvd->session_id != session_id) {
        fatal("unexpected rcvd session id: %d, expected: %d", rcvd->session_id, session_id);
    }

    fprintf(stderr, "<-- RCVD \n");
}

void udpr(struct sockaddr_in *server_address, char *buf, size_t buf_size) {
    // Set up the UDP connection.
    int sock = udpr_setup_connection();

    // -------------- start the protocol --------------
    uint64_t session_id = updr_start_protocol(sock, server_address, buf_size);

    // -------------- send the data --------------
    static data_packet_t last_data_packet;
    udpr_send_data_packets(sock, server_address, session_id, buf, buf_size, &last_data_packet);

    // -------------- end the protocol --------------
    udpr_receive_rcvd_packet(sock, server_address, session_id, &last_data_packet, sizeof(last_data_packet));

    // Close the connection.
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
    while (1) {
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
//    if (strcmp(protocol, "tcp") != 0 && strcmp(protocol, "udp") != 0 && strcmp(protocol, "udpr") != 0)
//        fatal("unknown protocol: %s", protocol);
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
        tcp(&server_address, buf, buf_size);
    } else if (strcmp(protocol, "udp") == 0) {
        udp(&server_address, buf, buf_size);
    } else if (strcmp(protocol, "udpr") == 0) {
        udpr(&server_address, buf, buf_size);
    } else {
        ClientUDPR(buf, buf_size, server_address, port).run();
    }

    free(buf);
    return 0;
}
