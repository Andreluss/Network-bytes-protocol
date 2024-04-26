#include <algorithm>
#include <stdexcept>
#include "Client.h"
#include "common.h"
#include "protocol.h"

void Client::run() {
    try {
        sock = create_connection_socket();
        struct timeval tv = {
                .tv_sec = MAX_WAIT,
                .tv_usec = 0
        };
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            syserr("setsockopt - setting receive timeout");

        ppcb_establish_connection();
        ppcb_send_data();
        ppcb_end_connection();
    }
    catch (const ppcb_exception& e) {
        fatal("%s", e.what());
    }
    catch (const std::runtime_error& e) {
        fatal("[runtime error] %s", e.what());
    }
}

void Client::ppcb_establish_connection() {
    session_id = random_64();
    conn_packet conn; conn_packet_init(&conn, session_id, c_protocol_id, data_to_send_size);
    send_packet_to_server(&conn, sizeof(conn)); debug("--> CONN \n");

    // receive packet from server which should be either conacc or connrjt
    uint8_t packet_type = receive_packet_from_server([&](int type, void* buf) {
        if (type == CONACC_PACKET_TYPE) {
            auto* conacc = (conacc_packet*) buf;
            if (conacc->session_id != session_id) {
                throw ppcb_exception("invalid session id: " + std::to_string(conacc->session_id) + ", expected: " + std::to_string(session_id));
            }
            return true;
        }
        else if (type == CONRJT_PACKET_TYPE) {
            auto* conrjt = (conrjt_packet*) buf;
            if (conrjt->session_id != session_id) {
                throw ppcb_exception("invalid session id: " + std::to_string(conrjt->session_id) + ", expected: " + std::to_string(session_id));
            }
            return true;
        }
        else {
            throw ppcb_exception("invalid packet: " + packet_short_info(type, buf, false) + ", expected CONACC or CONRJT");
        }
    });
    debug("<-- %s\n", packet_type == CONACC_PACKET_TYPE ? "CONACC" : "CONRJT");
    if (packet_type == CONRJT_PACKET_TYPE) {
        throw ppcb_exception("connection rejected - shutting down");
    }
}

void Client::ppcb_send_data() {
    char* data_ptr = (char*) data_to_send;
    size_t data_left = data_to_send_size;
    uint64_t packet_number = 0;
    while (data_left > 0) {
        size_t data_length = std::min(data_left, (size_t)DATA_PACKET_DATA_LENGTH);
        data_packet_t data_packet; data_packet_init(&data_packet, session_id, packet_number, data_length, data_ptr);

        send_packet_to_server(&data_packet, DATA_PACKET_HEADER_LENGTH + data_length);
        debug("--> DATA #%zu [%zu bytes]\n", packet_number, data_length);

        if (c_data_ack) {
            ppcb_get_ack(packet_number);
        }

        data_ptr += data_length;
        data_left -= data_length;
        packet_number++;
    }
}

void Client::ppcb_get_ack(uint64_t packet_number) {
    debug("[%zu] ", packet_number);
    uint8_t packet_type = receive_packet_from_server([&](int type, void* buf) {
        // At this point, we are sure the packet is readable and came from the server.
        // Now the options are:
        // - to return true if the packet is the expected one
        // - to return false if the client should ignore the packet and wait for the next one
        // - to throw an exception if the packet is too bad to be ignored and the client should stop
        if (type == ACC_PACKET_TYPE) {
            auto* acc = (acc_packet*) buf;
            if (acc->packet_number < packet_number) {
                return false;
            }
            if (acc->packet_number > packet_number) {
                throw ppcb_exception("invalid packet number: " + std::to_string(acc->packet_number) + ", expected: " + std::to_string(packet_number));
            }
            if (acc->session_id != session_id) {
                throw ppcb_exception("invalid session id: " + std::to_string(acc->session_id) + ", expected: " + std::to_string(session_id));
            }
            debug("<-- ACC #%zu\n", acc->packet_number);
            return true;
        }
        else if (type == RJT_PACKET_TYPE) {
            auto* rjt = (rjt_packet*) buf;
            if (rjt->session_id != session_id) {
                throw ppcb_exception("invalid session id: " + std::to_string(rjt->session_id) + ", expected: " + std::to_string(session_id));
            }
            debug("<-- RJT #%zu\n", rjt->packet_number);
            return true;
        }
        else if (type == CONACC_PACKET_TYPE) return false; // if the old retransmissions came just now
        else {
            throw ppcb_exception("invalid packet type: " + packet_short_info(type, buf, false) + ", expected ACC or RJT");
        }
    });

    if (packet_type == RJT_PACKET_TYPE) {
        throw ppcb_exception("data packet rejected - shutting down");
    } assert(packet_type == ACC_PACKET_TYPE);
}

void Client::ppcb_end_connection() {
    receive_packet_from_server([&](int type, void* buf) {
        if (type == ACC_PACKET_TYPE || type == CONACC_PACKET_TYPE) return false;
        if (type == RCVD_PACKET_TYPE) {
            auto* rcvd = (rcvd_packet*) buf;
            if (rcvd->session_id != session_id) {
                throw ppcb_exception("<- rcvd: invalid session id: " + std::to_string(rcvd->session_id) + ", expected: " + std::to_string(session_id));
            }
            // print in green
            debug("\033[1;32m<-- RCVD\033[0m\n");
            return true;
        }
        else if (type == RJT_PACKET_TYPE) {
            auto* rjt = (rjt_packet*) buf;
            if (rjt->session_id != session_id) {
                throw ppcb_exception("rjt: invalid session id: " + std::to_string(rjt->session_id) + ", expected: " + std::to_string(session_id));
            }
            // print in red
            debug("\033[1;31m<-- CONRJT\033[0m\n");
            return true;
        }
        else {
            throw ppcb_exception("[end of proto] invalid packet type: " + std::to_string(type) + ", expected RCVD");
        }
    });

}
