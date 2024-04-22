#ifndef NETWORK_BYTES_PROTOCOL_SERVERUDP_H
#define NETWORK_BYTES_PROTOCOL_SERVERUDP_H

#include "Server.h"

class ServerUDP : public Server {
public:
    explicit ServerUDP(int port);
    ~ServerUDP() = default;
    void setup_socket() override;
protected:
    void ppcb_establish_connection() override;
    void ppcb_receive_data() override;
    void ppcb_end_connection() override;

    bool try_receive_packet(const std::function<bool(int, void *)> &match_packet,
                            bool accept_all_senders, uint8_t *received_packet_type);
    // This function check and saves the received packet to recv_buffer,
    // returns the packet type and sets the recv_client_address and recv_client_address_len.
    uint8_t receive_packet(std::function<bool(int type, void *buf)> match_packet, bool from_everyone) override;
    struct sockaddr_in recv_client_address{};
    socklen_t recv_client_address_len = sizeof(recv_client_address);

    // This function sends the packet to the client and sets the last_packet_sent and last_packet_sent_size.
    void send_packet(void* packet, size_t packet_size) override;

    // The number of retransmissions for the current session (0 iff the session is not retransmitted).
    int retransmissions = 0;
    // The last packet sent in the current session (used for retransmissions).
    char last_packet_sent[MAX_PACKET_SIZE]{};
    size_t last_packet_sent_size = 0;
};


#endif //NETWORK_BYTES_PROTOCOL_SERVERUDP_H
