#include "Server.h"
#include "protconst.h"
#include <stdexcept>
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
    sigaction(SIGINT, &action, nullptr);

    for(;;) {
        try {
            new_session();
        }
        catch (const ppcb_exception& e) {
            fprintf(stderr, "ERROR: %s ->- disconnected /x.x\\\n", e.what());
        }
        catch (const std::runtime_error& e) {
            error("runtime-error -> %s", e.what());
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
    connection_fd = socket(AF_INET, socket_type, 0);
    if (connection_fd < 0) {
        syserr("cannot create a socket");
    }

    // Bind the socket to a concrete address.
    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces.
    server_address.sin_port = htons(port);
    if (bind(connection_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        syserr("bind");
    }
}

