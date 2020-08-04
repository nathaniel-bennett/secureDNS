#ifndef DNSWRAPPER__CACHE_H
#define DNSWRAPPER__CACHE_H

#include <netdb.h>

#include "resource_records.h"


dns_rr *get_cached_record(const char *hostname);

int add_record_to_cache(const char *hostname, dns_rr *resp);

int del_cached_record(const char *hostname);


#endif
