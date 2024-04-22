//
// Created by User on 4/21/2024.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include <cassert>
#include "ServerUDP.h"
#include "protconst.h"
#include "protocol.h"
#include <cinttypes>

ServerUDP::ServerUDP(int port): Server(port) {
}

void ServerUDP::setup_socket() {
    _setup_socket_with(SOCK_DGRAM);
}

void ServerUDP::ppcb_establish_connection() {
    fprintf(stderr, "<*> ");

    session.session_fd = connection_socket_fd; // the same as the server socket
    // Wait for a connection packet.
    // todo: set the timeout to inf and wait for the connection packet
    auto type = receive_packet([](int type, void *buf) {
        return type == CONN_PACKET_TYPE;
    }, true);
    fprintf(stderr, "CONN "); assert(type == CONN_PACKET_TYPE);
    auto* conn = (conn_packet*) recv_buffer;
    if (conn->protocol_id != UDP_PROTOCOL_ID && conn->protocol_id != UDPR_PROTOCOL_ID) {
        throw ppcb_exception("invalid protocol id, expected: UDP_PROTOCOL_ID or UDPR_PROTOCOL_ID, "
                             "got " + std::to_string(conn->protocol_id));
    }
    assert(conn->data_length >= 1 && conn->data_length <= DATA_PACKET_MAX_DATA_LENGTH);

    // Initialize the session.
    session.session_fd = connection_socket_fd; // the same as the server socket
    // in tcp, here we would listen and accept a tcp connection which would have a new socket fd
    session.data_length = conn->data_length;
    session.session_id = conn->session_id;
    if (conn->protocol_id == UDPR_PROTOCOL_ID) {
        fprintf(stderr, "[R ON] ");
        retransmissions = MAX_RETRANSMITS;
    }
    else {
        fprintf(stderr, "[R OFF] ");
        retransmissions = 0;
    }
    session.client_address = recv_client_address;
    fprintf(stderr, "from %s:%d\n", inet_ntoa(recv_client_address.sin_addr), ntohs(recv_client_address.sin_port));

    _set_socket_recv_timeout(session.session_fd, MAX_WAIT, 0);

    conacc_packet conacc; conacc_packet_init(&conacc, session.session_id);
    fprintf(stderr, "--> CONACC\n");
    send_packet(&conacc, sizeof(conacc));
}

#include <chrono>
// Tries to receive a packet, returns true if the packet was received and matched the match_packet function.
// (The received packet is saved in recv_buffer and matches the requirements.)
// if received_packet_type is not nullptr, it is set to the type of the received packet.
bool ServerUDP::try_receive_packet(const std::function<bool(int, void *)> &match_packet, bool accept_all_senders, uint8_t *received_packet_type) {
    int64_t microseconds_left = MAX_WAIT * 1000 * 1000;
    while (microseconds_left > 0) {
        _set_socket_recv_timeout(session.session_fd, static_cast<int>(microseconds_left / 1000000),
                                                     static_cast<int>(microseconds_left % 1000000));

        using std::chrono::system_clock, std::chrono::time_point, std::chrono::duration_cast, std::chrono::microseconds;
        time_point<system_clock> start = system_clock::now();
        ssize_t received_length = recvfrom(session.session_fd, recv_buffer, MAX_PACKET_SIZE, 0,
                                           (struct sockaddr *) &recv_client_address, &recv_client_address_len);
        time_point<system_clock> end = system_clock::now();
        auto elapsed = duration_cast<microseconds>(end - start).count();
        microseconds_left -= elapsed;

        // 1. check if the packet was received
        if (received_length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            else {
                throw std::runtime_error("recvfrom");
            }
        }

        try {
            // 2. check if the packet is not corrupted and process it
            auto packet_type = validate_packet(recv_buffer, received_length);
            if (received_packet_type != nullptr) *received_packet_type = packet_type;

            // 3. check the sender of the packet
            if (!accept_all_senders) {
                // if the sender is not the same as the client
                if (recv_client_address.sin_addr.s_addr != session.client_address.sin_addr.s_addr ||
                    recv_client_address.sin_port != session.client_address.sin_port) {
                    if (packet_type == CONN_PACKET_TYPE) {
                        auto* conn = (conn_packet*) recv_buffer;
                        // if the other client sends CONN, then answer with CONRJT
                        conrjt_packet conrjt; conrjt_packet_init(&conrjt, conn->session_id);
                        send_packet(&conrjt, sizeof(conrjt));
                        throw ppcb_exception("--> CONRJT to " + std::to_string(recv_client_address.sin_addr.s_addr) +
                                             ":" + std::to_string(recv_client_address.sin_port));
                    }
                    else {
                        throw ppcb_exception("<-- [packet " + std::to_string(packet_type) + "] from not-connected sender: " + std::to_string(recv_client_address.sin_addr.s_addr) +
                                             ":" + std::to_string(recv_client_address.sin_port));
                    }
                }
            }

            // 4. check if the packet matches the requirements
            if (match_packet(packet_type, recv_buffer)) {
                return true;
            }
            else {
                throw ppcb_exception("packet does not match the requirements");
            }
        }
        catch (ppcb_exception &e) {
            fprintf(stderr, "x-- SKIP (%s) \n", e.what());
            continue;
        }
    }
    return false;
}

// TODO: add second function for receive_from_all - the non-blocking version without retransmission
uint8_t ServerUDP::receive_packet(std::function<bool(int type, void *buf)> match_packet, bool from_everyone) {
    uint8_t packet_type = 0;
    for (int retransmissions_left = retransmissions; ; retransmissions_left--) {
        // try to receive a packet, retransmit if needed and possible
        bool need_to_retransmit = not try_receive_packet(match_packet, from_everyone, &packet_type);

        if (not need_to_retransmit) {
            return packet_type;
        } else {
            if (retransmissions_left > 0) {
                fprintf(stderr, "--RETRANSMIT (%d tries left)-> \n", retransmissions_left - 1);
                send_packet(last_packet_sent, last_packet_sent_size);
                continue;
            } else {
                throw ppcb_exception("/x.x\\ TIMEOUT - PACKET " + std::to_string(packet_type) + " DIDN'T ARRIVE");
            }
        }
    }
}

void ServerUDP::send_packet(void *packet, size_t packet_size) {
    if (packet_size == 0) return;
    auto bytes_sent = sendto(session.session_fd, packet, packet_size, 0,
           (struct sockaddr *) &recv_client_address, recv_client_address_len);
    if (bytes_sent != packet_size) {
        throw ppcb_exception("sendto: sent " + std::to_string(bytes_sent) + " bytes,"
                             " expected: " + std::to_string(packet_size));
    }

    memcpy(last_packet_sent, packet, packet_size);
    last_packet_sent_size = packet_size;
}

void ServerUDP::ppcb_receive_data() {
    auto send_rjt = [&](data_packet_t* data) {
        fprintf(stderr, "--> RJT\n");
        rjt_packet rjt; rjt_packet_init(&rjt, data->session_id, data->packet_number);
        send_packet(&rjt, sizeof(rjt));
    };
    for (uint64_t packet_number = 0, bytes_received = 0; bytes_received < session.data_length; packet_number++) {
        auto type = receive_packet([&](int type, void *buf) {
            // ensure the DATA packet type
            if (type != DATA_PACKET_TYPE) return false;
            auto* data = (data_packet_t*) buf;

            // ensure the correct session
            if (session.session_id != data->session_id) return false;

            // ensure the non-obsoleted packet number
            return data->packet_number >= packet_number;
        }, false);
        auto* data = (data_packet_t*) recv_buffer;
        fprintf(stderr, "<-- DATA "); assert(type == DATA_PACKET_TYPE);
        fprintf(stderr, "packet #%" PRIu64 " ", data->packet_number);
        fprintf(stderr, "with %" PRIu32 "B\n", data->data_length);

        // check if the packet number is correct
        if (packet_number != data->packet_number) {
            send_rjt(data);
            throw ppcb_exception("invalid packet number: " + std::to_string(data->packet_number) +
                                 ", expected: " + std::to_string(packet_number));
        }
        // check an edge-case: the last packet may have too much data
        bytes_received += data->data_length;
        if (bytes_received > session.data_length) {
            send_rjt(data);
            throw ppcb_exception("too much data received: " + std::to_string(bytes_received) +
                                 ", expected: " + std::to_string(session.data_length));
        }
        // --------------- data is correct ---------------

        // [print the data] to stdout
        print_data_packet(data);

        // send the ACC confirmation to the client if the protocol is UDPR
        if (retransmissions > 0) {
            fprintf(stderr, "--> ACC\n");
            acc_packet acc; acc_packet_init(&acc, session.session_id, packet_number);
            send_packet(&acc, sizeof(acc));
        }
    }
}

void ServerUDP::ppcb_end_connection() {
    fprintf(stderr, "--> RCVD \n");
    rcvd_packet rcvd; rcvd_packet_init(&rcvd, session.session_id);
    send_packet(&rcvd, sizeof(rcvd));
}

