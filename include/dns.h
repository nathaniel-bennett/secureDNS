#ifndef DNSWRAPPER__DNS_H
#define DNSWRAPPER__DNS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#undef EAI_BADFLAGS
#define EAI_BADFLAGS   -1  /* Invalid value for `ai_flags' field.  */

#undef EAI_NONAME
#define EAI_NONAME     -2  /* NAME or SERVICE is unknown.  */

#undef EAI_AGAIN
#define EAI_AGAIN      -3  /* Temporary failure in name resolution.  */

#undef EAI_FAIL
#define EAI_FAIL       -4  /* Non-recoverable failure in name res.  */

#ifdef __USE_GNU
#undef EAI_NODATA
#endif

#define EAI_NODATA     -5


#undef EAI_FAMILY
#define EAI_FAMILY     -6  /* `ai_family' not supported.  */

#undef EAI_SOCKTYPE
#define EAI_SOCKTYPE   -7  /* `ai_socktype' not supported.  */

#undef EAI_SERVICE
#define EAI_SERVICE    -8  /* SERVICE not supported for `ai_socktype'.  */

#ifdef __USE_GNU
#undef EAI_ADDRFAMILY
#endif

#define EAI_ADDRFAMILY -9


#undef EAI_MEMORY
#define EAI_MEMORY     -10 /* Memory allocation failure.  */

#undef EAI_SYSTEM
#define EAI_SYSTEM     -11 /* System error returned in `errno'.  */

#define EAI_TLS        -13

#define EAI_WANT_READ  -14

#define EAI_WANT_WRITE -15


#define AI_TLS 0x2000
#define AI_NONBLOCKING 0x4000

int getaddrinfo_fd(const char *node);

int WRAPPER_getaddrinfo(const char *node, const char *service,
            const struct addrinfo *hints, struct addrinfo **res);

void WRAPPER_freeaddrinfo(struct addrinfo *res);

const char *WRAPPER_gai_strerror(int errcode);


#define getaddrinfo(node, service, hints, res) \
            WRAPPER_getaddrinfo(node, service, hints, res)

#define freeaddrinfo(res) WRAPPER_freeaddrinfo(res)

#define gai_strerror(errcode) WRAPPER_gai_strerror(errcode)

#endif
