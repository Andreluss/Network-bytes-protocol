#include "Server.h"
#include "protconst.h"
#include <exception>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>

void Server::run() {
    setup_socket();

    // Signal handling - to ensure that the server will close the port.
    struct sigaction action{};
    action.sa_handler = [](int sig) {
        fprintf(stderr, "\\['']/ Signal %d received - closing!\n", sig);
        exit(0);
    };
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);

    for(;;) {
        try {
            new_session();
        }
        catch (const std::exception& e) {
            error("ERROR: %s", e.what());
        }

    }
}

void Server::new_session() {
    ppcb_establish_connection();
    ppcb_receive_data();
    ppcb_end_connection();
}

void Server::_setup_socket_with(int socket_type) {
    // Create a socket of the appropriate type.
    connection_socket_fd = socket(AF_INET, socket_type, 0);
    if (connection_socket_fd < 0) {
        syserr("cannot create a socket");
    }

    // Bind the socket to a concrete address.
    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces.
    server_address.sin_port = htons(port);
    if (bind(connection_socket_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        syserr("bind");
    }
}

void Server::_set_socket_recv_timeout(int socket_fd, int timeout_seconds, int timeout_microseconds) {
    struct timeval tv = {
            .tv_sec = timeout_seconds,
            .tv_usec = timeout_microseconds
    };
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        syserr("setsockopt");
}
