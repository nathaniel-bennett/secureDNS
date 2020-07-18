#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

#include "original_dns.h"
#include "addrinfo.h"
#include "../include/dns.h"
#include "dns_context.h"
#include "cache.h"
#include "dns_hashmap.h"
#include "resource_records.h"

#define CLOUDFARE_IP ((in_addr_t) 0x01010101)
#define DNS_OVER_TLS_PORT 853


static in_addr_t dns_addr = 0x00000000;


int check_bad_input(const char *node,
            const char *service, const struct addrinfo *hints);

int get_errno_error();
void clear_global_errors();

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
    errno = 0;

    if (hints == NULL || !(hints->ai_flags & AI_TLS))
        return o_getaddrinfo(node, service, hints, res);

    response = check_bad_input(node, service, hints);
    if (response != 0)
        return response;

    /* Check to see if the cached response will work */
    records = get_cached_record(node);
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
            response = get_errno_error();
            goto end;
        }

        dns_ctx->state = DNS_CONNECTING_TLS;

        /* FALL THROUGH */
    case DNS_CONNECTING_TLS:
        ret = SSL_connect(dns_ctx->ssl);
        if (ret != 1) {
            response = get_ssl_error(dns_ctx, ret);
            goto end;
        }

        response = form_dns_requests(dns_ctx, node);
        if (response != 0)
            goto end;

        dns_ctx->state = DNS_SENDING_REQUESTS;

        /* FALL THROUGH */
    case DNS_SENDING_REQUESTS:
        do {
            size_t cur_sent = 0;
            ret = SSL_write_ex(dns_ctx->ssl,
                               &dns_ctx->send_buf[dns_ctx->num_sent],
                               dns_ctx->req_size - dns_ctx->num_sent,
                               &cur_sent);

            dns_ctx->num_sent += cur_sent;
        } while (ret == 1 && dns_ctx->num_sent < dns_ctx->req_size);

        if (ret != 1) {
            response = get_ssl_error(dns_ctx, ret);
            goto end;
        }

        dns_ctx->state = DNS_RECEIVING_RESPONSES;

        /* FALL THROUGH */
    case DNS_RECEIVING_RESPONSES:
        do {
            size_t curr_read = 0;
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
            goto end;
        }

        response = parse_dns_records(dns_ctx->recv_buf,
                                     dns_ctx->resp_size, node, dns_ctx->id,
                                     &records);
        if (response != 0)
            goto end;

        response = convert_records(records, service, hints, res);

        /* we want to cache the good response regardless of conversion fail */
        ret = add_record_to_cache(node, records);
        if (ret != 0)
            dns_records_free(records);
    }

end:
    if (response == EAI_WANT_READ || response == EAI_WANT_WRITE) {
        clear_global_errors();
        return response;
    }


    del_dns_context(node);

    if (dns_ctx != NULL)
        dns_context_free(dns_ctx);

    return response;
}

int getaddrinfo_fd(const char *node)
{
    dns_context *dns_ctx = get_dns_context(node);
    if (dns_ctx == NULL)
        return -1;
    else
        return dns_ctx->fd;
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
    switch (errcode) {
    case EAI_BADFLAGS:
        return "Bad value for ai_flags";
    case EAI_NONAME:
        return "Name or service not known";
    case EAI_AGAIN:
        return "Temporary failure in name resolution";
    case EAI_FAIL:
        return "Non-recoverable failure in name resolution";
    case EAI_NODATA:
        return "No address associated with hostname";
    case EAI_FAMILY:
        return "ai_family not supported";
    case EAI_SOCKTYPE:
        return "ai_socktype not supported";
    case EAI_SERVICE:
        return "Servname not supported for ai_socktype";
    case EAI_ADDRFAMILY:
        return "Address family for hostname not supported";
    case EAI_MEMORY:
        return "Could not allocate memory sufficient to complete request";
    case EAI_SYSTEM:
        return "System error";
    case EAI_WANT_READ:
        return "Reading data from dns server would block";
    case EAI_WANT_WRITE:
        return "Sending data to dns server would block";
    case EAI_TLS:
        return "Authentication error with dns server";
    default:
        return "Unknown error";
    }
}





int check_bad_input(const char *node,
            const char *service, const struct addrinfo *hints)
{
    /* test node */
    if (node == NULL)
        return EAI_NONAME;

    /* test service */
    errno = 0;
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


int get_errno_error()
{
    switch (errno) {
    case EAGAIN:
    case EALREADY:
    case EINPROGRESS:
        return EAI_WANT_WRITE;
    case ENETUNREACH:
    case ENETRESET:
    case ENETDOWN:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    case ECONNREFUSED:
    case ECONNRESET:
    case ECONNABORTED:
    case ETIMEDOUT:
        return EAI_AGAIN;
    default:
        return EAI_FAIL;
    }
}

void clear_global_errors()
{
    errno = 0;
    ERR_clear_error();
}

