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

#define EAI_TLS        -12

#define EAI_WANT_READ  -13

#define EAI_WANT_WRITE -14

/** Flag to have `getaddrinfo()` lookups with DNS over TLS */
#define AI_TLS 0x2000

/** Flag to have `getaddrinfo()` return prematurely rather than blocking */
#define AI_NONBLOCKING 0x4000


/**
 * Returns the file descriptor being used internally to retrieve DNS records 
 * for the hostname @p node. The file descriptor is suitable for use with
 * `select()`, `poll()` or other system calls used to multiplex I/O. The return
 * value of a prior `getaddrinfo()` for @p node should be used to determine
 * whether reading or writing should be listened for on the socket (for
 * instance, one would set polling events for the file descriptor to `POLLIN`
 * if a call to `getaddrinfo()` returned `EAI_WANT_READ`; conversely the 
 * polling events would be set to `POLLOUT` if `EAI_WANT_WRITE` was returned). 
 * 
 * It should be noted that there is an in-memory DNS cache implemented for this 
 * stub resolver; as a result a call to `getaddrinfo()` may return a response 
 * immediately even if the `AI_NONBLOCKING` flag is set. Any code utilizing 
 * non-blocking DNS resolution should take this into account. 
 * @param node A hostname that has had a call to `getaddrinfo()` performed on 
 * it with the non-blocking flag set AND that has returned either 
 * `EAI_WANT_READ` or `EAI_WANT_WRITE` (a file descriptor will not be retrieved 
 * if any other value was returned by the call to `getaddrinfo()`). 
 * @return The file descriptor in use internally for the DNS lookup of @p 
 * node, or -1 if @p node does not have a non-blocking lookup in process. 
 */
int getaddrinfo_fd(const char *node);


/**
 * Sets the address of the recursive resolver to be connected to for DNS over 
 * TLS lookups. If @p addr is 0, the default resolver (1.1.1.1) will be used
 * and the @p hostname will be ignored. This function should not be called
 * while non-blocking DNS lookups are being performed, as any pending lookups
 * will be dropped and their associated file descriptors will be closed.
 * @param addr The recursive resolver server address to be used for DoT DNS 
 * lookups. This address should be in network byte order (which can be 
 * accomplished by using the `htonl()` function on most systems).
 * @param hostname The hostname associated with the recursive resolver. The 
 * hostname of the recursive resolver is required for adequate certificate 
 * verification to be performed in the TLS handshake. @p hostname must be a
 * null-terminated ASCII string that does not exceed 253 characters in length.
 * @return 0 if successfull; or -1 if an error occured (either `hostname` 
 * is null or its string length exceeds the maximum size).
 */
int getaddrinfo_set_resolver(in_addr_t addr, char *hostname);


/**
 * Retrieves the address of the recursive resolver server currently in use 
 * by the `getaddrinfo()` function for DNS over TLS lookups.
 * @param addr The IPv4 address of the recursive resolver to use. The returned 
 * address will be in network byte order (which can be converted 
 * using the `ntohl()` function on most systems). 
 */
in_addr_t getaddrinfo_resolver_addr();

/**
 * Retrieves the hostname of the recursive resolver in use for DNS over TLS
 * queries. This hostname is a null-terminated string that will not exceed
 * 253 characters in size (not including the null-terminating bit).
 * @returns The hostname of the recursive resolver currently being used.
 */
char *getaddrinfo_resolver_hostname();


int WRAPPER_getaddrinfo(const char *node, const char *service,
            const struct addrinfo *hints, struct addrinfo **res);

void WRAPPER_freeaddrinfo(struct addrinfo *res);

const char *WRAPPER_gai_strerror(int errcode);


#define getaddrinfo(node, service, hints, res) \
            WRAPPER_getaddrinfo(node, service, hints, res)

#define freeaddrinfo(res) WRAPPER_freeaddrinfo(res)

#define gai_strerror(errcode) WRAPPER_gai_strerror(errcode)

#endif
