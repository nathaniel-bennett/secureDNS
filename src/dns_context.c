#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "dns_context.h"
#include "resource_records.h"
#include "../include/dns.h"
#include "dns_hashmap.h"

#define BLOCK_PADDING_LENGTH 256
#define MAX_CERT_CHAIN_DEPTH 5
#define MAX_HOSTNAME_LEN 253
#define MAX_HOSTNAME_LABEL_LEN 63

#define RESP_LEN_BYTESIZE 2

#define CLOUDFARE_HOSTNAME "cloudflare-dns.com"
#define UBUNTU_CA_FOLDER "/etc/ssl/certs"


static SSL_CTX *ssl_ctx = NULL; /* to allow for session resumption/caching */

void setup_ssl_ctx();
void cleanup_ssl_ctx();

int canonicalize_name(const char *name, char **canon_name);



dns_context *dns_context_new(const char *hostname, int is_nonblocking)
{
    dns_context *dns_ctx = NULL;
    int ret;

    if (ssl_ctx == NULL) {
        setup_ssl_ctx();

        if (ssl_ctx == NULL)
            goto err;
    }

    dns_ctx = calloc(1, sizeof(dns_context));
    if (dns_ctx == NULL)
        return NULL;

    if (is_nonblocking)
        dns_ctx->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    else
        dns_ctx->fd = socket(AF_INET, SOCK_STREAM, 0);

    if (dns_ctx->fd == -1)
        goto err;

    dns_ctx->ssl = SSL_new(ssl_ctx);
    if (dns_ctx->ssl == NULL)
        goto err;

    ret = SSL_set1_host(dns_ctx->ssl, CLOUDFARE_HOSTNAME);
    if (ret != 1)
        goto err;

    ret = SSL_set_tlsext_host_name(dns_ctx->ssl, CLOUDFARE_HOSTNAME);
    if (ret != 1)
        goto err;

    ret = SSL_set_fd(dns_ctx->ssl, dns_ctx->fd);
    if (ret != 1)
        goto err;

    dns_ctx->state = DNS_CONNECTING_TCP;

    dns_ctx->resp_size = RESP_LEN_BYTESIZE;
    dns_ctx->responses_left = DNS_REQUEST_CNT;

    ret = add_dns_context(hostname, dns_ctx);
    if (ret != 0)
        goto err;

    return dns_ctx;

err:
    if (dns_ctx != NULL)
        dns_context_free(dns_ctx);

    return NULL;
}


void dns_context_free(dns_context *dns_ctx)
{
    if (dns_ctx->fd != -1)
        close(dns_ctx->fd);

    if (dns_ctx->ssl != NULL)
        SSL_free(dns_ctx->ssl);


    free(dns_ctx);
}


void setup_ssl_ctx()
{
    int ret;

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == NULL)
        goto err;

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    ret = SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
        goto err;

    ret = SSL_CTX_set_ciphersuites(ssl_ctx, "TLS_CHACHA20_POLY1305_SHA256:"
                                            "TLS_AES_256_GCM_SHA384");
    if (ret != 1)
        goto err;

    int ops = SSL_CTX_get_options(ssl_ctx);
    SSL_CTX_set_options(ssl_ctx, ops | SSL_OP_NO_COMPRESSION);

    SSL_CTX_set_block_padding(ssl_ctx, BLOCK_PADDING_LENGTH);

    ret = SSL_CTX_load_verify_locations(ssl_ctx, NULL, UBUNTU_CA_FOLDER);
    if (ret != 1)
        goto err;

    SSL_CTX_set_verify_depth(ssl_ctx, MAX_CERT_CHAIN_DEPTH);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    atexit(cleanup_ssl_ctx);
    return;

err:
    if (ssl_ctx != NULL)
        SSL_CTX_free(ssl_ctx);
    ssl_ctx = NULL;
}

void cleanup_ssl_ctx()
{
    SSL_CTX_free(ssl_ctx);
}


int form_dns_requests(dns_context *dns_ctx, const char *hostname)
{
    int ret;
    uint16_t id;

    char *canon_hostname = NULL;

    ret = RAND_bytes((unsigned char*) &id, sizeof(id));
    if (ret != 1)
        id = rand();

    dns_ctx->id = id;

    ret = canonicalize_name(hostname, &canon_hostname);
    if (ret != 0)
        goto err;

    ret = form_question_record(&dns_ctx->send_buf[2],
                               MAX_BUFFER - 2, id, canon_hostname, AF_INET);
    if (ret < 0)
        goto err;

    /* set the length of the message in the first two bytes of the message */
    dns_ctx->send_buf[0] = ret >> 8;
    dns_ctx->send_buf[1] = ret & 0xff;

    dns_ctx->req_size = ret + 2;

    ret = form_question_record(&dns_ctx->send_buf[dns_ctx->req_size + 2],
                               MAX_BUFFER - 2, id, canon_hostname, AF_INET6);
    if (ret < 0)
        goto err;

    free(canon_hostname);

    /* set the length of the message in the first two bytes of the message */
    dns_ctx->send_buf[dns_ctx->req_size] = ret >> 8;
    dns_ctx->send_buf[dns_ctx->req_size+1] = ret & 0xff;

    dns_ctx->req_size += ret + 2;

    return 0;
err:
    if (canon_hostname != NULL)
        free(canon_hostname);
    return ret;
}


int get_ssl_error(dns_context *dns_ctx, int ssl_ret)
{
    switch (SSL_get_error(dns_ctx->ssl, ssl_ret)) {
    case SSL_ERROR_WANT_READ:
        return EAI_WANT_READ;

    case SSL_ERROR_WANT_WRITE:
        return EAI_WANT_WRITE;

    case SSL_ERROR_SSL:
        return EAI_TLS;

    case SSL_ERROR_ZERO_RETURN:
        return EAI_AGAIN;

    default:
        return EAI_TLS;
    }
}

void parse_next_resp_size(dns_context *dns_ctx)
{
    size_t prev_size = dns_ctx->resp_size - RESP_LEN_BYTESIZE;
    size_t next_response_size = (dns_ctx->recv_buf[prev_size] << 8)
                + dns_ctx->recv_buf[prev_size+1];

    dns_ctx->num_read = prev_size;
    dns_ctx->resp_size = prev_size + next_response_size;

    dns_ctx->responses_left -= 1;
    if (dns_ctx->responses_left > 0)
        dns_ctx->resp_size += RESP_LEN_BYTESIZE;

    if (dns_ctx->resp_size > MAX_BUFFER) /* avoid buffer overflow */
        dns_ctx->resp_size = MAX_BUFFER;
}


int canonicalize_name(const char *name, char **canon_name)
{
    int label_len = 0, name_len, i;
    char *str;

    str = strdup(name);
    if (str == NULL)
        return EAI_MEMORY;

    /* leave the root zone alone */
    if (strcmp(str, ".") == 0) {
        *canon_name = str;
        return 0;
    }

    name_len = strlen(name);
    if (name_len == 0 || name_len > MAX_HOSTNAME_LEN)
        goto err;

    for (i = 0; i < name_len; i++) {
        /* make all upper-case letters lower case */
        if (str[i] >= 'A' && str[i] <= 'Z')
            str[i] += 32;

        if ((str[i] > '9' || str[i] < '0') && str[i] != '-' &&
                    (str[i] > 'z' || str[i] < 'a') && str[i] != '.')
            goto err;

        if (str[i] == '.') {
            if (label_len == 0)
                goto err;
            else
                label_len = 0;

        } else {
            label_len++;
        }

        if (label_len > MAX_HOSTNAME_LABEL_LEN)
            goto err;
    }

    /* remove the trailing dot, if any */
    if (str[name_len - 1] == '.')
        str[name_len - 1] = '\0';

    *canon_name = str;
    return 0;
err:
    free(str);
    return EAI_NONAME;
}