#include <netdb.h>
#include <stdlib.h>
#include <string.h>

#include "original_dns.h"

#define NEW_EAI_BADFLAGS   -1
#define NEW_EAI_NONAME     -2
#define NEW_EAI_AGAIN      -3
#define NEW_EAI_FAIL       -4
#define NEW_EAI_NODATA     -5
#define NEW_EAI_FAMILY     -6
#define NEW_EAI_SOCKTYPE   -7
#define NEW_EAI_SERVICE    -8
#define NEW_EAI_ADDRFAMILY -9
#define NEW_EAI_MEMORY     -10
#define NEW_EAI_SYSTEM     -11


int o_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res) {
    struct addrinfo *curr;
    struct sockaddr *tmp;

    int ret = getaddrinfo(node, service, hints, res);

    switch (ret) {
    case EAI_BADFLAGS:
        return NEW_EAI_BADFLAGS;

    case EAI_NONAME:
        return NEW_EAI_NONAME;

    case EAI_AGAIN:
        return NEW_EAI_AGAIN;

    case EAI_FAIL:
        return NEW_EAI_FAIL;

#ifdef __USE_GNU
    case EAI_NODATA:
        return NEW_EAI_NODATA;

    case EAI_ADDRFAMILY:
        return NEW_EAI_ADDRFAMILY;
#endif

    case EAI_FAMILY:
        return NEW_EAI_FAMILY;

    case EAI_SOCKTYPE:
        return NEW_EAI_SOCKTYPE;

    case EAI_SERVICE:
        return NEW_EAI_SERVICE;

    case EAI_MEMORY:
        return NEW_EAI_MEMORY;

    case EAI_SYSTEM:
        return NEW_EAI_SYSTEM;

    case 0:
        curr = *res;
        while (curr != NULL) {
            tmp = malloc(curr->ai_addrlen);
            if (tmp == NULL) {
                freeaddrinfo(*res);
                return NEW_EAI_MEMORY;
            }

            memcpy(tmp, curr->ai_addr, curr->ai_addrlen);
            curr->ai_addr = tmp;

            curr = curr->ai_next;
        }
        return 0;

    default:
        return NEW_EAI_FAIL;
    }
}
