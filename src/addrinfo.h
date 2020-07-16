#ifndef DNSWRAPPER_ADDRINFO_H
#define DNSWRAPPER_ADDRINFO_H

#include "resource_records.h"


int convert_records(dns_rr *records, const char *service,
            const struct addrinfo *hints, struct addrinfo **res);


#endif
