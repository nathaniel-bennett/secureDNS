#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "original_dns.h"
#include "addrinfo.h"
#include "../include/dns.h"
#include "dns_context.h"
#include "dns_cache.h"
#include "dns_hashmap.h"
#include "resource_records.h"

#define CLOUDFARE_IP ((in_addr_t) 0x01010101)
#define DNS_OVER_TLS_PORT 853


static in_addr_t dns_addr = 0x00000000;


int check_bad_input(const char *node,
            const char *service, const struct addrinfo *hints);


/**
 * Adds additional functionality to the usual getaddrinfo function, and
 *
 * @param node
 * @param service
 * @param hints
 * @param res
 * @return
 */
int WRAPPER_getaddrinfo(const char *node, const char *service,
            const struct addrinfo *hints, struct addrinfo **res)
{
    const struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(dns_addr == 0 ? CLOUDFARE_IP : dns_addr),
        .sin_port = htons(DNS_OVER_TLS_PORT),
    };
    dns_context *dns_ctx = NULL;
    dns_rr *records = NULL;
    int ret, response;

    if (hints == NULL || !(hints->ai_flags & AI_TLS))
        return o_getaddrinfo(node, service, hints, res);

    response = check_bad_input(node, service, hints);
    if (response != 0)
        return response;

    /* Check to see if the cached response will work */
    records = get_cached_dns(node);
    if (records != NULL)
        return convert_records(records, service, hints, res);

    dns_ctx = get_dns_context(node);
    if (dns_ctx == NULL) {
        dns_ctx = dns_context_new(node, hints->ai_flags & AI_NONBLOCKING);
        if (dns_ctx == NULL)
            return EAI_MEMORY;
    }

    switch (dns_ctx->state) {
    case DNS_CONNECTING_TCP:
        ret = connect(dns_ctx->fd, (struct sockaddr*) &addr, sizeof(addr));
        if (ret != 0) {
            if (errno == EAGAIN || errno == EALREADY || errno == EINPROGRESS) {
                return dns_ctx->fd;
            } else {
                response = EAI_AGAIN; /* TODO: change to specific error */
                goto end;
            }
        }

        dns_ctx->state = DNS_CONNECTING_TLS;

        /* FALL THROUGH */
    case DNS_CONNECTING_TLS:
        ret = SSL_connect(dns_ctx->ssl);
        if (ret != 1) {
            response = get_ssl_error(dns_ctx, ret);
            if (response < 0)
                goto end;
        }

        response = form_dns_requests(dns_ctx, node);
        if (response != 0)
            goto end;

        dns_ctx->state = DNS_SENDING_REQUESTS;

        /* FALL THROUGH */
    case DNS_SENDING_REQUESTS:
        do {
            size_t cur_sent;
            ret = SSL_write_ex(dns_ctx->ssl,
                               &dns_ctx->send_buf[dns_ctx->num_sent],
                               dns_ctx->req_size - dns_ctx->num_sent,
                               &cur_sent);

            dns_ctx->num_sent += cur_sent;
        } while (ret == 1 && dns_ctx->num_sent < dns_ctx->req_size);

        if (ret != 1) {
            response = get_ssl_error(dns_ctx, ret);
            if (response < 0)
                goto end;
        }

        dns_ctx->state = DNS_RECEIVING_RESPONSES;

        /* FALL THROUGH */
    case DNS_RECEIVING_RESPONSES:
        do {
            size_t curr_read;
            ret = SSL_read_ex(dns_ctx->ssl,
                              &dns_ctx->recv_buf[dns_ctx->num_read],
                              dns_ctx->resp_size - dns_ctx->num_read,
                              &curr_read);

            dns_ctx->num_read += curr_read;
            if (dns_ctx->responses_left > 0 && done_reading_response(dns_ctx))
                    parse_next_resp_size(dns_ctx);

        } while (ret == 1 && !done_reading_response(dns_ctx));

        if (ret != 1) {
            response = get_ssl_error(dns_ctx, ret);
            if (response < 0)
                goto end;
        }

        response = parse_dns_responses(dns_ctx->recv_buf,
                    dns_ctx->resp_size, node, dns_ctx->id, &records);
        if (response != 0)
            goto end;


        response = convert_records(records, service, hints, res);

        /* we want to cache the good response regardless of conversion fail */
        ret = add_to_dns_cache(node, records);
        if (ret != 0)
            dns_records_free(records);
    }

end:

    del_dns_context(node);

    if (dns_ctx != NULL)
        dns_context_free(dns_ctx);

    return response;
}

void WRAPPER_freeaddrinfo(struct addrinfo *res)
{
    if (res->ai_addr != NULL)
        free(res->ai_addr);
    if (res->ai_canonname != NULL)
        free(res->ai_canonname);
    if (res->ai_next != NULL)
        WRAPPER_freeaddrinfo(res->ai_next);

    free(res);
}


const char *WRAPPER_gai_strerror(int errcode)
{
    /* TODO: account for non-defined GNU error codes */

    if (errcode != EAI_TLS)
        return o_gai_strerror(errcode);

    return NULL; /* TODO: stub */
}





int check_bad_input(const char *node,
            const char *service, const struct addrinfo *hints)
{
    /* test node */
    if (node == NULL)
        return EAI_NONAME;

    /* test service */
    long port = strtol(service, NULL, 10);
    if (port < 0 || port >= USHRT_MAX || errno != 0)
        return EAI_SERVICE;

    /* test hints */
    if (hints->ai_flags & (AI_PASSIVE))
        return EAI_BADFLAGS;

    if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET
        && hints->ai_family != AF_INET6)
        return EAI_FAMILY;

    if (hints->ai_socktype != 0 && hints->ai_socktype != SOCK_STREAM
        && hints->ai_socktype != SOCK_DGRAM)
        return EAI_SOCKTYPE;

    if (hints->ai_protocol != 0 && hints->ai_protocol != IPPROTO_TCP
        && hints->ai_protocol != IPPROTO_UDP)
        return EAI_SERVICE;


    if (hints->ai_socktype == SOCK_RAW)
        return EAI_SERVICE;
    if (hints->ai_socktype == SOCK_STREAM
                && hints->ai_protocol == IPPROTO_UDP)
        return EAI_SOCKTYPE;
    if (hints->ai_socktype == SOCK_DGRAM
                && hints->ai_protocol == IPPROTO_TCP)
        return EAI_SOCKTYPE;

    return 0;
}

