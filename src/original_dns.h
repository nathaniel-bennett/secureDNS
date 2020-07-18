#ifndef DNSWRAPPER__ORIGINAL_DNS_H
#define DNSWRAPPER__ORIGINAL_DNS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


int o_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res);

#endif
