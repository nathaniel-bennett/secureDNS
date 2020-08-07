#ifndef DNSWRAPPER__SOCKET_HASHMAP_H
#define DNSWRAPPER__SOCKET_HASHMAP_H

#include "dns_context.h"

dns_context *get_saved_dns_context(const char *hostname);

int add_saved_dns_context(const char *hostname, dns_context *dns_ctx);

int del_saved_dns_context(const char *hostname);

void clear_saved_dns_contexts();

#endif
