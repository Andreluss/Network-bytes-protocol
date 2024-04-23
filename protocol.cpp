#include "protocol.h"


void conn_packet_init(conn_packet *packet, uint64_t session_id, uint8_t protocol_id, uint64_t data_length) {
    packet->type = CONN_PACKET_TYPE;
    packet->session_id = session_id;
    packet->protocol_id = protocol_id;
    packet->data_length = htobe64(data_length);
}

// Initialize a conacc_packet struct
void conacc_packet_init(conacc_packet *packet, uint64_t session_id) {
    packet->type = CONACC_PACKET_TYPE;
    packet->session_id = session_id;
}

// Initialize a conrjt_packet struct
void conrjt_packet_init(conrjt_packet *packet, uint64_t session_id) {
    packet->type = CONRJT_PACKET_TYPE;
    packet->session_id = session_id;
}

// Initialize a data_packet_t struct
void data_packet_init(data_packet_t *packet, uint64_t session_id, uint64_t packet_number, uint32_t data_length, char* data) {
    packet->type = DATA_PACKET_TYPE;
    packet->session_id = session_id;
    packet->packet_number = htobe64(packet_number);
    packet->data_length = htobe32(data_length);
    assert(data_length <= DATA_PACKET_MAX_DATA_LENGTH);
    memcpy(&packet->data, data, data_length);
}

// Initialize an acc_packet struct
void acc_packet_init(acc_packet *packet, uint64_t session_id, uint64_t packet_number) {
    packet->type = ACC_PACKET_TYPE;
    packet->session_id = session_id;
    packet->packet_number = htobe64(packet_number);
}

// Initialize an rjt_packet struct
void rjt_packet_init(rjt_packet *packet, uint64_t session_id, uint64_t packet_number) {
    packet->type = RJT_PACKET_TYPE;
    packet->session_id = session_id;
    packet->packet_number = htobe64(packet_number);
}

// Initialize an rcvd_packet struct
void rcvd_packet_init(rcvd_packet *packet, uint64_t session_id) {
    packet->type = RCVD_PACKET_TYPE;
    packet->session_id = session_id;
}


// Scans the buffer for a packet, converts its bytes to host order and returns the packet type.
// If the packet is corrupted, ppcb_exception is thrown.
uint8_t validate_packet(void* buf, size_t buf_size) {
    if (buf_size < 1) throw ppcb_exception("empty packet");
    uint8_t packet_type = *(uint8_t*)buf;
    if (packet_type == CONN_PACKET_TYPE) {
        if (buf_size != sizeof(conn_packet))
            throw ppcb_exception("invalid CONN packet size");

        auto* conn = (conn_packet*)buf;
        if (conn->protocol_id != TCP_PROTOCOL_ID && conn->protocol_id != UDP_PROTOCOL_ID && conn->protocol_id != UDPR_PROTOCOL_ID)
            throw ppcb_exception("invalid protocol id");

        conn->data_length = be64toh(conn->data_length);
        if (conn->data_length < 1 || conn->data_length > DATA_PACKET_MAX_DATA_LENGTH)
            throw ppcb_exception("invalid data length");
    }
    else if (packet_type == CONACC_PACKET_TYPE) {
        if (buf_size != sizeof(conacc_packet)) throw ppcb_exception("invalid CONACC packet size");
    }
    else if (packet_type == CONRJT_PACKET_TYPE) {
        if (buf_size != sizeof(conrjt_packet)) throw ppcb_exception("invalid CONRJT packet size");
    }
    else if (packet_type == DATA_PACKET_TYPE) {
        if (buf_size < DATA_PACKET_HEADER_LENGTH) throw ppcb_exception("invalid DATA packet size");
        auto* data = (data_packet_t*)buf;
        data->packet_number = be64toh(data->packet_number);
        data->data_length = be32toh(data->data_length);
        if (data->data_length < 1 || data->data_length > DATA_PACKET_MAX_DATA_LENGTH)
            throw ppcb_exception("invalid data length");
    }
    else if (packet_type == ACC_PACKET_TYPE) {
        if (buf_size != sizeof(acc_packet)) throw ppcb_exception("invalid ACC packet size");
        auto* acc = (acc_packet*)buf;
        acc->packet_number = be64toh(acc->packet_number);
    }
    else if (packet_type == RJT_PACKET_TYPE) {
        if (buf_size != sizeof(rjt_packet)) throw ppcb_exception("invalid RJT packet size");
        auto* rjt = (rjt_packet*)buf;
        rjt->packet_number = be64toh(rjt->packet_number);
    }
    else if (packet_type == RCVD_PACKET_TYPE) {
        if (buf_size != sizeof(rcvd_packet)) throw ppcb_exception("invalid RCVD packet size");
    }
    else throw ppcb_exception("unexpected packet type");

    return packet_type;
}

int print_data_packet(data_packet_t *data_packet, const std::string &end) {
    if (writen(STDOUT_FILENO, data_packet->data, data_packet->data_length) != data_packet->data_length) {
        error("write (received data)");
        return -1;
    }
    // flush stdout to make sure the data is printed
    fflush(stdout);

    fprintf(stderr, "<-- [");
    writen(STDERR_FILENO, data_packet->data, data_packet->data_length);
    fprintf(stderr, "]%s", end.c_str());

    return 0;
}

// Reads, but doesn't really validate the packet from the stream (e.g. tcp socket).
// Returns the number of bytes read or -1 if an error occurred.
ssize_t read_packet_from_stream(int sock, void* buffer) {
    char* ptr = (char*) buffer;

    // read the first byte to determine the packet type
    if (readn(sock, ptr, 1) <= 0) return -1;
    ssize_t total_bytes_read = 1;
    uint8_t packet_type = *ptr;
    ptr += 1;

    auto read_n_bytes = [&](ssize_t n)->ssize_t {
        ssize_t bytes_read = readn(sock, ptr, n);
        if (bytes_read != n) return -1;
        total_bytes_read += bytes_read;
        ptr += bytes_read;
        return bytes_read;
    };

    if (packet_type == CONN_PACKET_TYPE) {
        if (read_n_bytes(sizeof(conn_packet)-1) < 0) return -1;
        return total_bytes_read;
    } else if (packet_type == CONACC_PACKET_TYPE) {
        if (read_n_bytes(sizeof(conacc_packet)-1) < 0) return -1;
        return total_bytes_read;
    } else if (packet_type == CONRJT_PACKET_TYPE) {
        if (read_n_bytes(sizeof(conrjt_packet)-1) < 0) return -1;
        return total_bytes_read;
    } else if (packet_type == DATA_PACKET_TYPE) {
        if (read_n_bytes(DATA_PACKET_HEADER_LENGTH - 1) < 0) return -1;
        uint32_t data_length = ((data_packet_t*) buffer)->data_length;
        data_length = be32toh(data_length);
        if (data_length > DATA_PACKET_MAX_DATA_LENGTH || data_length == 0) {
            fprintf(stderr, "~ tcp read - invalid data length: %d\n", data_length);
            return -1;
        }
        if (read_n_bytes(data_length) < 0) return -1;
        return total_bytes_read;
    } else if (packet_type == ACC_PACKET_TYPE) {
        if (read_n_bytes(sizeof(acc_packet)-1) < 0) return -1;
        return total_bytes_read;
    } else if (packet_type == RJT_PACKET_TYPE) {
        if (read_n_bytes(sizeof(rjt_packet)-1) < 0) return -1;
        return total_bytes_read;
    } else if (packet_type == RCVD_PACKET_TYPE) {
        if (read_n_bytes(sizeof(rcvd_packet)-1) < 0) return -1;
        return total_bytes_read;
    } else {
        return -1;
    }
}
