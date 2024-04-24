#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <endian.h>
#include <exception>
#include <string>
#include <cstring>
#include <stdio.h>
#include <cstdlib>
#include <cassert>
#include <utility>
#include "protconst.h"
#include "common.h"
#include <unistd.h>

#define MAX_PACKET_SIZE 65535
#define DATA_PACKET_MAX_DATA_LENGTH 64000
#define DATA_PACKET_DATA_LENGTH 1024

#define CONN_PACKET_TYPE 1
#define CONACC_PACKET_TYPE 2
#define CONRJT_PACKET_TYPE 3
#define DATA_PACKET_TYPE 4
#define ACC_PACKET_TYPE 5
#define RJT_PACKET_TYPE 6
#define RCVD_PACKET_TYPE 7

#define TCP_PROTOCOL_ID 1
#define UDP_PROTOCOL_ID 2
#define UDPR_PROTOCOL_ID 3

// CONN: Nawiązanie połączenia (K->S)
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t session_id;
    uint8_t protocol_id;
    uint64_t data_length;
} conn_packet;

// CONACC: Akceptacja połączenia (S->K)
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t session_id;
} conacc_packet;

// CONRJT: Odrzucenie połączenia (S->K)
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t session_id;
} conrjt_packet;

// DATA: Pakiet z danymi (nie zawsze wypeniany w calosci) (K->S)
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t session_id;
    uint64_t packet_number;
    uint32_t data_length;
    uint8_t data[DATA_PACKET_MAX_DATA_LENGTH];
} data_packet_t;
#define DATA_PACKET_HEADER_LENGTH (sizeof(data_packet_t)-DATA_PACKET_MAX_DATA_LENGTH)

// ACC: Potwierdzenie pakietu z danymi (S->K)
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t session_id;
    uint64_t packet_number;
} acc_packet;

// RJT: Odrzucenie pakietu z danymi (S->K)
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t session_id;
    uint64_t packet_number;
} rjt_packet;

// RCVD: Potwierdzenie otrzymania całego ciągu (S->K)
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint64_t session_id;
} rcvd_packet;

// Wszystkie liczby w porządku sieciowym są zapisane w kolejności bajtów big-endian (trzeba używać funkcji htonl, htons, ntohl, ntohs).

// headers:
void conn_packet_init(conn_packet *packet, uint64_t session_id, uint8_t protocol_id, uint64_t data_length);
void conacc_packet_init(conacc_packet *packet, uint64_t session_id);
void conrjt_packet_init(conrjt_packet *packet, uint64_t session_id);
void data_packet_init(data_packet_t *packet, uint64_t session_id, uint64_t packet_number, uint32_t data_length, char* data);
void acc_packet_init(acc_packet *packet, uint64_t session_id, uint64_t packet_number);
void rjt_packet_init(rjt_packet *packet, uint64_t session_id, uint64_t packet_number);
void rcvd_packet_init(rcvd_packet *packet, uint64_t session_id);


class ppcb_exception : public std::exception {
private:
    std::string message;
public:
    explicit ppcb_exception(std::string msg) noexcept : message(std::move(msg)) {}
    ppcb_exception(const ppcb_exception& other) noexcept = default;
    [[nodiscard]] const char* what () const noexcept override {
        return message.c_str();
    }
};

class ppcb_timeout_exception : public ppcb_exception {
public:
    explicit ppcb_timeout_exception(std::string msg) noexcept : ppcb_exception(std::move(msg)) {}
};

uint8_t validate_packet(void* buf, size_t buf_size);

int print_data_packet(data_packet_t *data_packet, const std::string &end = "\n");

ssize_t read_packet_from_stream(int sock, void* buffer);

std::string packet_short_info(uint8_t type, void* packet);

#endif
