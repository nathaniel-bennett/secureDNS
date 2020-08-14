#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#include "addrinfo.h"
#include "../include/securedns.h"


int convert_individual_record(dns_rr *record, const char *service,
    int family, int socktype, int protocol, struct addrinfo **res);

int assign_socktype(int socktype, int protocol);
int assign_protocol(int socktype, int protocol);
int next_socktype(int curr_socktype);

in_port_t str_to_port(const char *port, in_port_t *out);
int assign_port(const char *service, struct addrinfo *info);


int convert_records(dns_rr *records, const char *service,
            const struct addrinfo *hints, struct addrinfo **res)
{
    dns_rr *curr_record = records;
    struct addrinfo *last = NULL, *curr_info;

    int family = hints->ai_family;
    int socktype = assign_socktype(hints->ai_socktype, hints->ai_protocol);
    int protocol = assign_protocol(hints->ai_socktype, hints->ai_protocol);
    int response;

    *res = NULL;

    while (curr_record != NULL) {
        curr_info = NULL;
        response = convert_individual_record(curr_record,
                    service, family, socktype, protocol, &curr_info);
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
            socktype = next_socktype(socktype);
            protocol = assign_protocol(socktype, protocol);

            if (socktype == SOCK_STREAM)
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


int convert_individual_record(dns_rr *record, const char *service,
            int family, int socktype, int protocol, struct addrinfo **res)
{
    struct addrinfo *curr = NULL;
    int response;

    curr = calloc(1, sizeof(struct addrinfo));
    if (curr == NULL)
        return EAI_MEMORY;

    if (family != AF_UNSPEC && family != record->addr->sa_family) {
        response = EAI_ADDRFAMILY; /* TODO: resolve EAI_FAMILY in check_input */
        goto err;
    }
    else {
        curr->ai_family = record->addr->sa_family;
    }

    curr->ai_socktype = socktype;
    curr->ai_protocol = protocol;

    if (curr->ai_family == AF_INET)
        curr->ai_addrlen = sizeof(struct sockaddr_in);
    else
        curr->ai_addrlen = sizeof(struct sockaddr_in6);

    curr->ai_addr = malloc(curr->ai_addrlen);
    if (curr->ai_addr == NULL) {
        response = EAI_MEMORY;
        goto err;
    }

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

    else if (protocol == IPPROTO_TCP)
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

    else if (socktype == SOCK_STREAM)
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
 *
 * @param port
 * @param out The port number (in network byte order) to be used
 * @return
 */
in_port_t str_to_port(const char *port, in_port_t *out)
{
    long res;

    if (port == NULL)
        res = 0;
    else
        res = strtol(port, NULL, 10);

    if (res < 0 || res > UINT16_MAX || (res == 0 && strcmp(port, "0") != 0))
        return -1;

    *out = (in_port_t) htons((uint16_t) res);
    return 0;
}



int assign_port(const char *service, struct addrinfo *info)
{
    in_port_t port;

    if (str_to_port(service, &port) != 0)
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


