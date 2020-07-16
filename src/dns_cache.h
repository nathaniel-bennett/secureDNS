#ifndef DNSWRAPPER__DNS_CACHE_H
#define DNSWRAPPER__DNS_CACHE_H

#include <netdb.h>

#include "resource_records.h"

dns_rr *get_cached_dns(const char *hostname);

int add_to_dns_cache(const char *hostname, dns_rr *resp);

int del_cached_dns(const char *hostname);

void clear_dns_cache();


#endif
