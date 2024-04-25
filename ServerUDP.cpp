#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include "ServerUDP.h"
#include "protconst.h"
#include "protocol.h"
#include <cinttypes>

void ServerUDP::setup_socket() {
    _setup_socket_with(SOCK_DGRAM);
}

bool ServerUDP::check_recv_packet(const std::function<bool(int, void *)> &match_packet, ssize_t received_length,
                                  bool accept_all_senders) {
    // 1. check if the packet was received
    if (received_length < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false;
        }
        else {
            throw std::runtime_error("recvfrom - system function failed to receive packet");
        }
    }

    try {
        uint8_t packet_type;
        try {
            // 2. check if the packet is not corrupted and process it (if it is, function throws ppcb_exception)
            packet_type = validate_packet(recv_buffer, received_length);
        }
        catch (ppcb_exception &e) {
            if (!accept_all_senders && sockaddr_in_equal(recv_packet_address, session.client_address)) {
                // if the sender is the client, then we need to end the session
                throw e;
            }
            // if we don't care about the particular sender, we can ignore the corrupted packet
            throw ppcb_skipped_packed_exception(e.what());
        }

        // 3. check the sender of the packet
        if (!accept_all_senders) {
            // if the sender is not the same as the client

            if (!sockaddr_in_equal(recv_packet_address, session.client_address)) {
                if (packet_type == CONN_PACKET_TYPE) {
                    auto* conn = (conn_packet*) recv_buffer;
                    // if the other client sends CONN, then answer with CONRJT
                    conrjt_packet conrjt; conrjt_packet_init(&conrjt, conn->session_id);
                    send_packet_to_client(&conrjt, sizeof(conrjt));
                    throw ppcb_skipped_packed_exception("--> CONRJT to " + std::string(inet_ntoa(recv_packet_address.sin_addr)) +
                                         ":" + std::to_string(recv_packet_address.sin_port));
                }
                else {
                    throw ppcb_skipped_packed_exception("[packet " + std::to_string(packet_type) + "] from unknown sender: "
                                    + std::string(inet_ntoa(recv_packet_address.sin_addr))
                                    + ":" + std::to_string(recv_packet_address.sin_port));
                }
            }
        }

        // 4. check if the packet matches the requirements
        if (match_packet(packet_type, recv_buffer)) {
            return true;
        }
        else {
            throw ppcb_skipped_packed_exception(packet_short_info(packet_type, recv_buffer, false));
        }
    }
    catch (ppcb_skipped_packed_exception &e) {
        fprintf(stderr, "x-- skip %s \n", e.what());
    }
    return false;
}

bool ServerUDP::try_receive_packet(const std::function<bool(int, void *)> &match_packet, uint8_t *received_packet_type) {
    int64_t microseconds_left = MAX_WAIT * 1000 * 1000;
    while (microseconds_left > 0) {
        set_socket_recv_timeout(session.session_fd, static_cast<int>(microseconds_left / 1000000),
                                                     static_cast<int>(microseconds_left % 1000000));
        ssize_t received_length{};
        microseconds_left -= measure_time_microseconds([&](){
            received_length = recvfrom(session.session_fd, recv_buffer, MAX_PACKET_SIZE, 0,
                                        (struct sockaddr *) &recv_packet_address, &recv_packet_address_len);
        });

        if (check_recv_packet(match_packet, received_length, false)) {
            if (received_packet_type != nullptr) {
                *received_packet_type = *(uint8_t*)recv_buffer;
            }
            return true;
        }
    }
    return false;
}

// --------------- send and receive api ---------------

uint8_t ServerUDP::receive_packet_from_client(const std::function<bool(int type, void *buf)>& match_packet) {
    uint8_t packet_type = 0;
    for (int retransmissions_left = retransmissions; ; retransmissions_left--) {
        // try to receive a packet, retransmit if needed and possible
        bool need_to_retransmit = not try_receive_packet(match_packet, &packet_type);

        if (not need_to_retransmit) {
            return packet_type;
        } else {
            if (retransmissions_left > 0) {
                fprintf(stderr, "-r> %s (try %d/%d)\n", packet_short_info(last_packet_sent_type, last_packet_sent,
                                                                          true).c_str(),
                        retransmissions - retransmissions_left + 1, retransmissions);
                send_packet_to_client(last_packet_sent, last_packet_sent_size);
                continue;
            } else {
                throw ppcb_timeout_exception(";_; Timeout - packet didn't arrive");
            }
        }
    }
}

uint8_t ServerUDP::receive_packet_from_all(std::function<bool(int, void *)> match_packet) {
    set_socket_recv_timeout(connection_fd, 0, 0); // blocking
    while (true) {
        ssize_t received_length = recvfrom(connection_fd, recv_buffer, MAX_PACKET_SIZE, 0,
                                           (struct sockaddr *) &recv_packet_address, &recv_packet_address_len);
        if (check_recv_packet(match_packet, received_length, true)) {
            return *(uint8_t*)recv_buffer;
        }
        fprintf(stderr, "<*> "); fflush(stderr);
    }
}

void ServerUDP::send_packet_to_client(void *packet, ssize_t packet_size) {
    if (packet_size == 0) return;
    ssize_t bytes_sent = sendto(session.session_fd, packet, packet_size, 0,
                             (struct sockaddr *) &recv_packet_address, recv_packet_address_len);
    if (bytes_sent != packet_size) {
        throw ppcb_exception("sendto: sent " + std::to_string(bytes_sent) + " bytes,"
                             " expected: " + std::to_string(packet_size));
    }

    uint8_t packet_type = *(uint8_t*)packet;
    if (packet_type == ACC_PACKET_TYPE || packet_type == CONACC_PACKET_TYPE) {
        // save only the packets for retransmission from server to client (ACC, CONACC)
        memcpy(last_packet_sent, packet, packet_size);
        last_packet_sent_size = packet_size;
        last_packet_sent_type = *(uint8_t*)packet;
    }
}

// --------------- Protocol functions ---------------

void ServerUDP::ppcb_establish_connection() {
    // Wait for a connection packet.
    fprintf(stderr, "<*> ");
    receive_packet_from_all([](int type, void */*buf*/) {
        return type == CONN_PACKET_TYPE;
    }); fprintf(stderr, "CONN ");
    auto* conn = (conn_packet*) recv_buffer;
    if (conn->protocol_id != UDP_PROTOCOL_ID && conn->protocol_id != UDPR_PROTOCOL_ID) {
        throw ppcb_exception("invalid protocol id, expected: UDP_PROTOCOL_ID or UDPR_PROTOCOL_ID, "
                             "got " + std::to_string(conn->protocol_id));
    }

    // Initialize the session.
    session.session_fd = connection_fd; // the same as the server socket in tcp, here we would listen and accept a tcp connection which would have a new socket fd
    session.data_length = conn->data_length;
    session.session_id = conn->session_id;
    session.client_address = recv_packet_address;
    if (conn->protocol_id == UDPR_PROTOCOL_ID) {
        fprintf(stderr, "UDPR [");
        retransmissions = MAX_RETRANSMITS;
    }
    else {
        fprintf(stderr, "UDP [");
        retransmissions = 0;
    }
    fprintf(stderr, "%s:%d]\n", inet_ntoa(recv_packet_address.sin_addr), ntohs(recv_packet_address.sin_port));

    // Send back the CONACC packet.
    conacc_packet conacc; conacc_packet_init(&conacc, session.session_id);
    fprintf(stderr, "--> CONACC\n");
    send_packet_to_client(&conacc, sizeof(conacc));
}

void ServerUDP::ppcb_receive_data() {
    auto send_rjt = [&](uint64_t packet_number) {
        fprintf(stderr, "--> RJT\n");
        rjt_packet rjt; rjt_packet_init(&rjt, session.session_id, packet_number);
        send_packet_to_client(&rjt, sizeof(rjt));
    };
    for (uint64_t packet_number = 0, bytes_received = 0; bytes_received < session.data_length; packet_number++) {
        try {
            receive_packet_from_client([&](int type, void *buf) {
                // ensure the DATA packet type
                if (type != DATA_PACKET_TYPE) return false;
                auto *data = (data_packet_t *) buf;

                // ensure the correct session
                if (session.session_id != data->session_id) return false;

                // ensure the non-obsoleted packet number
                return data->packet_number >= packet_number;
            });
        }
        catch (ppcb_exception &e) {
            auto* data = (data_packet_t*) recv_buffer;
            fprintf(stderr, " [exception-error] ");
            fflush(stderr);
            send_rjt(data->packet_number); // send RJT if the client sends an invalid packet
            throw;
        }
        auto* data = (data_packet_t*) recv_buffer;

        // check if the packet number is correct
        if (packet_number != data->packet_number) {
            send_rjt(data->packet_number);
            throw ppcb_exception("invalid packet number: " + std::to_string(data->packet_number) +
                                 ", expected: " + std::to_string(packet_number));
        }
        // check an edge-case: the last packet may have too much data
        bytes_received += data->data_length;
        if (bytes_received > session.data_length) {
            send_rjt(data->packet_number);
            throw ppcb_exception("too much data received: " + std::to_string(bytes_received) +
                                 ", expected: " + std::to_string(session.data_length));
        }
        // --------------- data is correct ---------------

        // [print the data] to stdout
        if (print_data_packet(data, " ") < 0) throw std::runtime_error("write (received data -> stdout)");

        // send the ACC confirmation to the client if the protocol is UDPR
        if (retransmissions > 0) {
            fprintf(stderr, "--> ACC");
            acc_packet acc; acc_packet_init(&acc, session.session_id, packet_number);
            send_packet_to_client(&acc, sizeof(acc));
        }
//        fprintf(stderr, (bytes_received < session.data_length) ? "\r" : "\n");
        fprintf(stderr, "\n");
    }
}

void ServerUDP::ppcb_end_connection() {
    fprintf(stderr, "--> RCVD \n");
    rcvd_packet rcvd; rcvd_packet_init(&rcvd, session.session_id);
    send_packet_to_client(&rcvd, sizeof(rcvd));
}
