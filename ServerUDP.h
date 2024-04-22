#ifndef NETWORK_BYTES_PROTOCOL_SERVERUDP_H
#define NETWORK_BYTES_PROTOCOL_SERVERUDP_H

#include "Server.h"

class ServerUDP : public Server {
public:
    explicit ServerUDP(int port): Server(port) {};
    ~ServerUDP() = default;
    void setup_socket() override;
protected:
    void ppcb_establish_connection() override;
    void ppcb_receive_data() override;
    void ppcb_end_connection() override;

    bool check_recv_packet(const std::function<bool(int, void *)> &match_packet, ssize_t received_length, bool accept_all_senders);

    // Tries to receive a packet, returns true if the packet was received and matched the match_packet function.
    // (The received packet is saved in recv_buffer and matches the requirements.)
    // if received_packet_type is not nullptr, it is set to the type of the received packet.
    bool try_receive_packet(const std::function<bool(int, void *)> &match_packet, uint8_t *received_packet_type);

    // These 2 functions check and save the received packet to recv_buffer,
    // returns the packet type and sets the recv_packet_address and recv_packet_address_len.
    // -> Non-blocking (timeout-ed) function - receive a matching packet from the session client.
    uint8_t receive_packet_from_client(const std::function<bool(int, void *)> &match_packet) override;
    // -> Blocking function - receive a matching packet from any sender.
    uint8_t receive_packet_from_all(std::function<bool(int type, void *buf)> match_packet) override;
    struct sockaddr_in recv_packet_address{};
    socklen_t recv_packet_address_len = sizeof(recv_packet_address);

    // This function sends the packet to the client and sets the last_packet_sent and last_packet_sent_size.
    void send_packet_to_client(void* packet, size_t packet_size) override;
    // The last packet sent in the current session (used for retransmissions).
    char last_packet_sent[MAX_PACKET_SIZE]{};
    size_t last_packet_sent_size = 0;

    // The number of retransmissions for the current session (0 iff the session is not retransmitted).
    int retransmissions = 0;
};


#endif //NETWORK_BYTES_PROTOCOL_SERVERUDP_H
