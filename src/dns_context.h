#ifndef DNSWRAPPER__DNS_CONTEXT_H
#define DNSWRAPPER__DNS_CONTEXT_H

#include <openssl/ssl.h>

#define MAX_BUFFER 8192
#define DNS_REQUEST_CNT 2


typedef struct dns_context_st dns_context;


#define done_reading_response(dns_ctx) \
            ((dns_ctx)->num_read == (dns_ctx)->resp_size)



enum dns_state {
    DNS_CONNECTING_TCP,
    DNS_CONNECTING_TLS,
    DNS_SENDING_REQUESTS,
    DNS_RECEIVING_RESPONSES,
};



struct dns_context_st {

    int fd;
    SSL *ssl;

    uint16_t id;
    enum dns_state state;

    unsigned char send_buf[MAX_BUFFER];
    size_t num_sent;
    size_t req_size;

    unsigned char recv_buf[MAX_BUFFER];
    size_t num_read;
    size_t resp_size;

    int responses_left;
};


dns_context *dns_context_new(const char *hostname, int is_nonblocking);
void dns_context_free(dns_context *dns_ctx);

int form_dns_requests(dns_context *dns_ctx, const char *hostname);

int get_ssl_error(dns_context *dns_ctx, int ssl_ret);

void parse_next_resp_size(dns_context *dns_ctx);





#endif
