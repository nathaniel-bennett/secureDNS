#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#include "addrinfo.h"
#include "../include/securedns.h"


int convert_individual_record(dns_rr *record,
    const char *service, struct addrinfo hints, struct addrinfo **res);

void ipv4_map_to_ipv6(struct sockaddr_in *in, struct sockaddr_in6 *out);

int assign_socktype(int socktype, int protocol);
int assign_protocol(int socktype, int protocol);
int next_socktype(int curr_socktype);

in_port_t str_to_port(const char *port);
int assign_port(const char *service, struct addrinfo *info);


int convert_records(dns_rr *records, const char *service,
            const struct addrinfo *hints, struct addrinfo **res)
{
    dns_rr *curr_record = records;
    struct addrinfo *last = NULL, *curr_info;

    struct addrinfo curr_hints = {
        .ai_family = hints->ai_family,
        .ai_flags = hints->ai_flags,
        .ai_socktype = assign_socktype(hints->ai_socktype, hints->ai_protocol),
        .ai_protocol = assign_protocol(hints->ai_socktype, hints->ai_protocol),
    };

    int response;

    *res = NULL;


    if (hints->ai_family != AF_INET6)
        curr_hints.ai_flags &= ~AI_V4MAPPED;

    /* IPv6 addresses are parsed first; if first record not IPv6, none are */
    if (curr_record->flags == 0 && curr_record->addr->sa_family == AF_INET6
                && !(curr_hints.ai_flags & AI_ALL))
        curr_hints.ai_flags &= ~AI_V4MAPPED;

    while (curr_record != NULL) {
        curr_info = NULL;
        response = convert_individual_record(curr_record,
                    service, curr_hints, &curr_info);
        if (response == 0) {
            if (!(hints->ai_flags & AI_CANONNAME)) {
                free(curr_info->ai_canonname);
                curr_info->ai_canonname = NULL;
            }

            if (*res == NULL)
                *res = curr_info;
            else
                last->ai_next = curr_info;

            last = curr_info;
        }

        if (hints->ai_socktype == 0 && hints->ai_protocol == 0) {
            /* in this case we iterate through all possible combinations */
            curr_hints.ai_socktype = next_socktype(curr_hints.ai_socktype);
            curr_hints.ai_protocol = assign_protocol(curr_hints.ai_socktype, curr_hints.ai_protocol);

            if (curr_hints.ai_socktype == SOCK_STREAM)
                curr_record = curr_record->next;

        } else {
            curr_record = curr_record->next;
        }
    }

    if (*res == NULL)
        return EAI_NODATA;
    else
        return 0;
}


int convert_individual_record(dns_rr *record,
            const char *service, struct addrinfo hints, struct addrinfo **res)
{
    struct addrinfo *curr = NULL;
    int response;

    curr = calloc(1, sizeof(struct addrinfo));
    if (curr == NULL)
        return EAI_MEMORY;

    curr->ai_socktype = hints.ai_socktype;
    curr->ai_protocol = hints.ai_protocol;

    if (hints.ai_flags & AI_V4MAPPED) {
        curr->ai_family = AF_INET6;

    } else if (hints.ai_family == AF_UNSPEC
                || hints.ai_family == record->addr->sa_family) {
        curr->ai_family = record->addr->sa_family;

    } else {
        response = EAI_ADDRFAMILY; /* TODO: resolve EAI_FAMILY in check_input */
        goto err;
    }


    if (record->addr->sa_family == AF_INET6 || (hints.ai_flags & AI_V4MAPPED))
        curr->ai_addrlen = sizeof(struct sockaddr_in6);
    else
        curr->ai_addrlen = sizeof(struct sockaddr_in);

    curr->ai_addr = malloc(curr->ai_addrlen);
    if (curr->ai_addr == NULL) {
        response = EAI_MEMORY;
        goto err;
    }

    if (record->addr->sa_family == AF_INET && (hints.ai_flags & AI_V4MAPPED))
        ipv4_map_to_ipv6((struct sockaddr_in*) record->addr,
                         (struct sockaddr_in6*) curr->ai_addr);
    else
        memcpy(curr->ai_addr, record->addr, curr->ai_addrlen);


    response = assign_port(service, curr);
    if (response != 0)
        goto err;

    curr->ai_canonname = strdup(record->cname);
    if (curr->ai_canonname == NULL) {
        response = EAI_MEMORY;
        goto err;
    }

    *res = curr;
    return 0;
err:

    freeaddrinfo(curr);
    return response;
}



void ipv4_map_to_ipv6(struct sockaddr_in *ipv4, struct sockaddr_in6 *ipv6)
{
    unsigned char *addr_ptr = (unsigned char*) &(ipv6->sin6_addr);

    memset(ipv6, 0, sizeof(struct sockaddr_in6));

    ipv6->sin6_family = AF_INET6;
    ipv6->sin6_port = ipv4->sin_port;

    memset(&(addr_ptr)[10], 0xff, 2);
    memcpy(&(addr_ptr)[12], &ipv4->sin_addr, sizeof(ipv4->sin_addr));
}


int next_socktype(int curr_socktype)
{
    if (curr_socktype == SOCK_STREAM)
        return SOCK_DGRAM;
    else if (curr_socktype == SOCK_DGRAM)
        return SOCK_RAW;
    else if (curr_socktype == SOCK_RAW)
        return SOCK_STREAM;

    return curr_socktype;
}




int assign_socktype(int socktype, int protocol)
{
    if (socktype == 0 && protocol == 0)
        return SOCK_STREAM;

    if (protocol == IPPROTO_TCP)
        return SOCK_STREAM;

    else if (protocol == IPPROTO_UDP)
        return SOCK_DGRAM;

    else
        return socktype;
}

int assign_protocol(int socktype, int protocol)
{
    if (socktype == 0 && protocol == 0)
        return IPPROTO_TCP;

    if (socktype == SOCK_STREAM)
        return IPPROTO_TCP;

    else if (socktype == SOCK_DGRAM)
        return IPPROTO_UDP;

    else if (socktype == SOCK_RAW)
        return 0;

    else
        return protocol;
}

/* TODO: add support for strings such as 'HTTP', 'DNS', etc? */
/**
 * @param port A string representation of a port number
 * @param out The port number (in network byte order) to be used
 * @return An integer port number (or -1 on failure)
 */
in_port_t str_to_port(const char *port)
{
    long res;

    if (port == NULL)
        return -1;

    res = strtol(port, NULL, 10);

    if (res < 0 || res > UINT16_MAX || (res == 0 && strcmp(port, "0") != 0))
        return -1;

    return (in_port_t) htons((uint16_t) res);
}


int assign_port(const char *service, struct addrinfo *info)
{
    in_port_t port = str_to_port(service);
    if (port < 0)
        return EAI_SERVICE;

    if (info->ai_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in*) info->ai_addr;
        addr->sin_port = port;

    } else {
        struct sockaddr_in6 *addr = (struct sockaddr_in6*) info->ai_addr;
        addr->sin6_port = port;
    }

    return 0;
}


