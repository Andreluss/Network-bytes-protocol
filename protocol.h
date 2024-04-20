#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <endian.h>
#include "protconst.h"

/*

Protokół Przesyłania Ciągów Bajtów
Zadanie polega na zaimplementowaniu poniżej opisanego protokołu oraz na wykonaniu testów wydajności swojej implementacji w różnych warunkach sieciowych.

Protokół
PPCB służy do przesyłania ciągu bajtów pomiędzy klientem a serwerem. Jako protokołu niższej warstwy używa TCP lub UDP, a połączenia korzystające z UDP mogą obsługiwać prosty mechanizm retransmisji. Trzeba więc zaimplementować trzy wersje protokołu. Ciąg bajtów jest przesyłany w paczkach o wielkości od 1 do 64000 bajtów. Każda paczka może mieć inną długość.

Komunikacja przebiega następująco (szczegółowe opisy zawartości pakietów znajdują się poniżej):

Nawiązanie połączenia

Gdy używany jest protokół TCP, klient tworzy połączenie TCP do serwera. Jeżeli serwer obsługuje już inne połączenie, to nie odbiera nowego do czasu zakończenia obsługi poprzedniego. Jeśli klientowi nie uda się nawiązać połączenia, to kończy działanie.

Klient wysyła pakiet CONN.

Serwer odsyła pakiet CONACC, jeśli przyjmuje połączenie. Serwer korzystający z TCP zawsze odpowiada w ten sposób. Serwer korzystający z UDP może być w trakcie obsługi innego połączenia, w takiej sytuacji odsyła pakiet CONRJT. Klient po otrzymaniu CONRJT kończy działanie.

Przesyłanie danych

Dopóki nie zostaną wysłane wszystkie dane:

Klient wysyła pakiet DATA o niezerowej długości.

Serwer po otrzymaniu pakietu DATA sprawdza, czy pochodzi on z aktualnie obsługiwanego połączenia, czy pakiet jest kolejnym pakietem danych i czy jest poprawny. Jeśli nie, to serwer odsyła pakiet RJT i przestaje obsługiwać to połączenie.

Poprawny pakiet jest potwierdzany przez serwer UDP z retransmisją poprzez odesłanie pakietu ACC, a serwery TCP i UDP nie wysyłają potwierdzeń.

Klient UDP z retransmisją czeka na otrzymanie ACC przed wysłaniem kolejnego pakietu.

Zakończenie

Po odebraniu wszystkich danych serwer TCP odsyła potwierdzenie odebrania danych RCVD, zamyka połączenie i przechodzi do obsługi kolejnych. Serwery UDP i UDP z retransmisją odsyłają potwierdzenie RCVD i przechodzą do obsługi kolejnych połączeń.

Po wysłaniu wszystkich danych i odebraniu potwierdzenia (RCVD) klient TCP zamyka połączenie i kończy działanie. Klient UDP i UDP z retransmisją kończy działanie.

W prawie każdym miejscu, w którym następuje oczekiwanie na odebranie pakietu, jeśli pakiet nie będzie otrzymany w trakcie MAX_WAIT sekund, program ma zakończyć obsługę danego połączenia bądź zażądać retransmisji. Nie dotyczy to oczekiwania przez serwer na nawiązanie nowego połączenia, które trwa dowolnie długo.

Mechanizm retransmisji działa następująco: jeśli w okresie MAX_WAIT nie zostanie otrzymane potwierdzenie odebrania wysłanych danych, to należy je wysłać ponownie. Czynność tę należy powtórzyć maksymalnie MAX_RETRANSMITS razy, a w przypadku niepowodzenia zakończyć obsługę połączenia. Potwierdzeniem odebrania wysłanych danych jest odebranie kolejnego pakietu wynikającego z przebiegu działania protokołu. Przykładowo, potwierdzeniem odebrania pakietu DATA jest pakiet ACC, a potwierdzeniem odebrania ACC jest kolejny pakiet z danymi. Potwierdzeniem CONN jest CONACC. Ostatni pakiet DATA jest potwierdzany pakietem ACC, który już nie jest potwierdzany. Serwer bezpośrednio po jednokrotnym wysłaniu tego ACC wysyła pakiet RCVD, który również nie jest potwierdzany. Serwer i klient ignorują ponownie otrzymane wcześniejsze pakiety (a więc DATA z wcześniejszym numerem pakietu lub CONN w przypaku serwera, natomiast ACC z wcześniejszym numerem pakietu lub CONACC w przypadku klienta).

Pakiety przesyłane przez protokół
Przesyłane pakiety składają się z pól o określonej długości występujących bezpośrednio po sobie, bez żadnych wypełnień pomiędzy polami.

Pakiety to:

CONN: Nawiązanie połączenia (K->S)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 1,
losowy identyfikator sesji: 64 bity; można je traktować jako ciąg bajtów albo liczbę,
identyfikator protokołu: 8 bitów; wartości to:
tcp: 1
udp: 2
udp z retransmisją: 3,
długość ciągu bajtów: 64 bity; liczba w porządku sieciowym.
CONACC: Akceptacja połączenia (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 2,
identyfikator sesji: 64 bity.
CONRJT: Odrzucenie połączenia (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 3,
identyfikator sesji: 64 bity.
DATA: Pakiet z danymi (K->S)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 4,
identyfikator sesji: 64 bity,
numer pakietu: 64 bity; liczba w porządku sieciowym,
liczba bajtów danych w pakiecie: 32 bity; liczba w porządku sieciowym,
dane: długość zależna od pola 3, ciąg bajtów.
ACC: Potwierdzenie pakietu z danymi (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 5,
identyfikator sesji: 64 bity,
numer pakietu: 64 bity; liczba w porządku sieciowym.
RJT: Odrzucenie pakietu z danymi (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 6,
identyfikator sesji: 64 bity,
numer pakietu: 64 bity; liczba w porządku sieciowym.
RCVD: Potwierdzenie otrzymania całego ciągu (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 7,
identyfikator sesji: 64 bity.

Wszystkie liczby w porządku sieciowym są zapisane w kolejności bajtów big-endian (trzeba używać funkcji htonl, htons, ntohl, ntohs).
*/

/* This is the file with protocol structs etc. */

/*
Pakiety przesyłane przez protokół
Przesyłane pakiety składają się z pól o określonej długości występujących bezpośrednio po sobie, bez żadnych wypełnień pomiędzy polami.

Pakiety to:

CONN: Nawiązanie połączenia (K->S)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 1,
losowy identyfikator sesji: 64 bity; można je traktować jako ciąg bajtów albo liczbę,
identyfikator protokołu: 8 bitów; wartości to:
tcp: 1
udp: 2
udp z retransmisją: 3,
długość ciągu bajtów: 64 bity; liczba w porządku sieciowym.
CONACC: Akceptacja połączenia (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 2,
identyfikator sesji: 64 bity.
CONRJT: Odrzucenie połączenia (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 3,
identyfikator sesji: 64 bity.
DATA: Pakiet z danymi (K->S)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 4,
identyfikator sesji: 64 bity,
numer pakietu: 64 bity; liczba w porządku sieciowym,
liczba bajtów danych w pakiecie: 32 bity; liczba w porządku sieciowym,
dane: długość zależna od pola 3, ciąg bajtów.
ACC: Potwierdzenie pakietu z danymi (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 5,
identyfikator sesji: 64 bity,
numer pakietu: 64 bity; liczba w porządku sieciowym.
RJT: Odrzucenie pakietu z danymi (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 6,
identyfikator sesji: 64 bity,
numer pakietu: 64 bity; liczba w porządku sieciowym.
RCVD: Potwierdzenie otrzymania całego ciągu (S->K)

identyfikator typu pakietu: 8 bitów; dla tego typu pakietów 7,
identyfikator sesji: 64 bity.

*/

#define MAX_PACKET_SIZE 65535
#define DATA_PACKET_MAX_SIZE sizeof(data_packet)
#define DATA_PACKET_MAX_DATA_LENGTH 64000

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
    packet->packet_number = packet_number;
}

// Initialize an rjt_packet struct
void rjt_packet_init(rjt_packet *packet, uint64_t session_id, uint64_t packet_number) {
    packet->type = RJT_PACKET_TYPE;
    packet->session_id = session_id;
    packet->packet_number = packet_number;
}

// Initialize an rcvd_packet struct
void rcvd_packet_init(rcvd_packet *packet, uint64_t session_id) {
    packet->type = RCVD_PACKET_TYPE;
    packet->session_id = session_id;
}

#endif
