#ifndef MIM_COMMON_H
#define MIM_COMMON_H

#include <cstddef>
#include <cstdint>
#include <sys/types.h>
#include <functional>
#define DEBUG 1

uint16_t read_port(char const *string);
struct sockaddr_in get_server_address(char const *host, uint16_t port);
ssize_t	readn(int fd, void *vptr, size_t n);
ssize_t	writen(int fd, const void *vptr, size_t n);
void install_signal_handler(int signal, void (*handler)(int));
uint64_t random_64();

void set_socket_recv_timeout(int socket_fd, int timeout_seconds, int timeout_microseconds);

[[noreturn]] void syserr(const char* fmt, ...);
[[noreturn]] void fatal(const char* fmt, ...);
void error(const char* fmt, ...);

void debug(const char* fmt, ...);

int64_t measure_time_microseconds(const std::function<void()> &fun);

// write a function (don't overload == operator) to compare two sockaddr_in structs
bool sockaddr_in_equal(const struct sockaddr_in &a, const struct sockaddr_in &b);

#endif
