#ifndef DNSWRAPPER__SOCKET_HASHMAP_H
#define DNSWRAPPER__SOCKET_HASHMAP_H

#include "dns_context.h"

dns_context *get_dns_context(const char *hostname);

int add_dns_context(const char *hostname, dns_context *dns_ctx);

int del_dns_context(const char *hostname);


#endif