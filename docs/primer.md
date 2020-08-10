# SecureDNS Primer

This document outlines how to go about using the SecureDNS library to perform 
DNS over TLS name resolution using the `getaddrinfo()` function. The library 
should be installed on your machine (see [install.md](install.md) for more 
information on this), and the following header function should be included 
at the top of any source files you intend to use DNS over TLS in:

```c
#include <securedns.h>
```

## A Refresher on `getaddrinfo` 

The following is taken from the `getaddrinfo` man page. 

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res);

void freeaddrinfo(struct addrinfo *res);

const char *gai_strerror(int errcode);
```

Given node and service, which identify an Internet host and a service, 
getaddrinfo() returns one or more addrinfo structures, each of which contains 
an Internet address that can be specified in a call to bind(2) or connect(2). 
The getaddrinfo() function combines the functionality provided by the 
gethostbyname(3) and getservbyname(3) functions into a single interface, but 
unlike the latter functions, getaddrinfo() is reentrant and allows programs to 
eliminate IPv4-versus-IPv6 dependencies.

The addrinfo structure used by getaddrinfo() contains the following fields:
```c
struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};
```
The `hints` argument points to an addrinfo structure that specifies criteria for 
selecting the socket address structures returned in the list pointed to by res. 
If hints is not NULL it points to an addrinfo structure whose ai_family, 
ai_socktype, and ai_protocol specify criteria that limit the set of socket 
addresses returned by getaddrinfo(), as follows:
> ### ai_family
>    This field specifies the desired address family for the
>    returned addresses.  Valid values for this field include
>    AF_INET and AF_INET6.  The value AF_UNSPEC indicates that
>    getaddrinfo() should return socket addresses for any address
>    family (either IPv4 or IPv6, for example) that can be used
>    with node and service.

> ### ai_socktype
>    This field specifies the preferred socket type, for example
>    SOCK_STREAM or SOCK_DGRAM.  Specifying 0 in this field indi‐
>    cates that socket addresses of any type can be returned by
>    getaddrinfo().

> ### ai_protocol
>    This field specifies the protocol for the returned socket
>    addresses.  Specifying 0 in this field indicates that socket
>    addresses with any protocol can be returned by getaddrinfo().

> ### ai_flags
>    This field specifies additional options, described below.
>    Multiple flags are specified by bitwise OR-ing them together.

All the other fields in the structure pointed to by hints must con‐
tain either 0 or a null pointer, as appropriate.

The `ai_flags` member of the `hints` structure may be populated with a 
combination of defined flags that are bitwise OR'ed together. For the sake 
of brevity, only flags that directly apply to DNS over TLS lookup will be 
listed here (flags such as `AI_PASSIVE` can be found in the man pages). 
The flags are:

> ### AI_TLS
> Performs the DNS lookup using TLS encryption over port 853 (DNS over TLS). 

> ### AI_NONBLOCKING
> Has the DNS lookup return early rather than blocking for connections or I/O. 
> If this flag is set, the `getaddrinfo` function will return `EAI_WOULD_READ` 
> if the internal connection is waiting on a read operation, or 
> `EAI_WOULD_WRITE` if the internal connection is waiting on a write operation. 
> Once the operation will complete without blocking, 0 will be returned. 
> This option may only be used in conjunction with `AI_TLS`. 

> ### AI_CANONNAME
> As the DNS lookup return the canon name associated with each address in the 
> returned addrinfo structure. This flag has no effect when `AI_TLS` is used, 
> as canon names are populated into the struct by default. 

## Applying DNS Over TLS Functionality to Existing Code

One of the SecureDNS library's main focuses is to make it trivially easy for 
existing code to upgrade plaintext DNS resolution to that of DNS over TLS. 
It is for this reason that the library wraps around existing functions 
rather than building a completely different API that may or may not work well 
with existing architectures. 

Take, for example, this code: 

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define HOSTNAME "nathanielbennett.com"
#define PORT "443"


int main(int argc, char *argv[]) {
    
    struct addrinfo *result;
    int fd, ret;

    struct addrinfo hints = {
        .ai_family = AF_INET6,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_NUMERICSERV;
    };

    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
        exit(1);

    ret = getaddrinfo(HOSTNAME, PORT, &hints, &result); 
    if (ret != 0 || result == NULL)
        exit(1);

    ret = connect(fd, result->ai_addr, result->ai_addrlen);
    if (ret != 0)
        exit(1);

    freeaddrinfo(result);
    
    /* continue... */
}
```

It creates a socket, performs DNS resolution on the hostname it intends 
to connect to, and then connects to the returned address. This is as 
minimal an example of the functions use as possible--we'll get on to the 
more versatile ways it can be used and how the SecureDNS library ties in 
to them later.

The next block of code shows all that is needed to convert the DNS lookup 
above into one that uses DNS over TLS:

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <securedns.h> 
        /* ^ included the library here */

#define HOSTNAME "nathanielbennett.com"
#define PORT "443"


int main(int argc, char *argv[]) {
    
    struct addrinfo *result;
    int fd, ret;

    struct addrinfo hints = {
        .ai_family = AF_INET6,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_NUMERICSERV | AI_TLS; /* <-- one flag here */
    };

    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
        exit(1);

    ret = getaddrinfo(HOSTNAME, PORT, &hints, &result); 
    if (ret != 0 || result == NULL)
        exit(1);

    ret = connect(fd, result->ai_addr, result->ai_addrlen);
    if (ret != 0)
        exit(1);

    freeaddrinfo(result);
    
    /* continue... */
}
```

For any given DNS lookup, all that needs to be done is including the library 
at the top of the source file and adding the `AI_TLS` flag into the `hints` 
struct. No other changes are needed--everything is done within the 
`getaddrinfo()` function, which remains completely unchanged. The returned 
structure will contain all the same entries which would have been contained 
in a normal DNS lookup, and DNS records will be automatically cached for the 
duration of their life in case additional lookups are done.


Now, for a more complete example of the `getaddrinfo()` function:

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define HOSTNAME "nathanielbennett.com"
#define PORT "443"


int main(int argc, char *argv[]) {
    
    struct addrinfo *result, *curr;
    int fd, ret;

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_NUMERICSERV;
    };

    ret = getaddrinfo(HOSTNAME, PORT, &hints, &result); 
    if (ret != 0 || result == NULL)
        exit(1);
    

    /* walk through the linked list of addresses */
    for (curr = result; curr = curr->ai_next; curr != NULL) {
        
        fd = socket(curr->ai_family, SOCK_STREAM, 0);
        if (fd < 1)
            continue;
        
        ret = connect(fd, curr->ai_addr, curr->ai_addrlen);
        if (ret == 0)
            break; /* connection succeeded */

        close(fd);
    }

    freeaddrinfo(result);

    if (curr == NULL)
        exit(1);
    
    /* if curr != NULL then fd is connected */

}
```

This example highlights a few more features of `getaddrinfo()`--the `for` loop 
allows for each address from the DNS lookup to be tried, and the `ai->family` 
field is used to connect transparently to either IPv4 or IPv6 addresses. 
Despite the increase in complexity, adding DNS over TLS support remains as 
simple as it was before--adding `#include <securedns>` and `AI_TLS` in the 
correct locations are all that is needed.

## Changing the Nameserver in use for DNS Over TLS

By default, any DNS over TLS lookups done through `getaddrinfo()` will query 
Cloudflare's [1.1.1.1](cloudflare-dns.com) nameserver. This was chosen as the 
default server because of its privacy policy and its speed. In the event that 
a user wants to switch the DNS resolver that will be queried in their code, the 
following function can be used:
```c
int getaddrinfo_set_nameserver(in_addr_t addr, char *hostname);
```
This function sets any subsequent queries to be sent to the nameserver with 
address `addr` and hostname `hostname`. The address passed in must be an 
IPv4 address in network byte order, and the hostname must be a null-terminated 
string of length no greater than 253 characters. When `addr` is 0, `hostname` 
will be ignored and the nameserver will be reset to its default 
address/hostname. If any asynchronous DNS lookups are in the process of being 
completed, they will be canceled and their file descriptors will be closed 
(we'll get to asynchronous DNS lookups later). If the hostname doesn't 
correctly correspond to the address being connected to, then the TLS handshake 
will fail and `EAI_TLS` will be returned as an error code when DNS lookup is 
attempted.

Two additional functions exist to retrieve the nameserver currently being 
used for DoT lookups:
```c
in_addr_t getaddrinfo_nameserver_addr();
const char *getaddrinfo_nameserver_hostname();
```
`getaddrinfo_nameserver_addr()` returns the IPv4 address of the current 
nameserver in network byte order. `getaddrinfo_nameserver_hostname` returns 
the hostname of the current nameserver in a statically-allocated buffer that 
should not be freed.

## Using Asynchronous DNS over TLS

The traditional `getaddrinfo()` function would block until a DNS lookup has 
fully completed sending/receiving information. There are some cases, however, 
where a non-blocking DNS lookup is desired or even required for a program to 
operate. Previous implementations (such as `getaddrinfo_a()`) have used 
signals and signal handlers to indicate when a lookup has been completed; 
these tend to add complexity to code and introduce difficult-to-catch bugs 
when signals interrupt certain functions. Because of this, nonblocking DNS 
over TLS resolution is instead handed via nonblocking sockets and multiplexing 
functions such as `select()` or `epoll()`.

To facilitate this, the SecureDNS library has a function that retrieves the 
file descriptor associated with a particular DNS query. This allows for a user 
to begin a DNS request using `getaddrinfo()` with the `AI_NONBLOCKING` flag, 
retrieve the file descriptor for that particular request, and use the file 
descriptor along with one of the aforementioned multiplexing functions to 
wait for it (along with any other file descriptors) to be ready. 

Those who have used `select()` or `poll()` in code before know that a file 
descriptor is waited on until it is either ready to read information in, or 
to write information out. Because of this, `getaddrinfo()` returns either 
`EAI_WANT_READ` or `EAI_WANT_WRITE` when in nonblocking mode so that the 
file descriptor may either be listened for reading or for writing. The 
following code example shows this in action using the `poll()` function:

```c
#include <sys/poll.h>
#include <netdb.h>
#include "<securedns.h>"

#define NUM_HOSTS 6
#define PORT "80"

const char *hosts[NUM_HOSTS] = {"example1.com", "example2.com", "example3.com"
                                "example4.com", "example5.com", "example6.com"};


int main(int argc, char **argv) {

    struct addrinfo *addresses[NUM_HOSTS];
    pollfd pfds[NUM_HOSTS] = {0};

    int num_querying = NUM_HOSTS;
    int ret, i;

    struct addrinfo hints = {
        .ai_flags = AI_TLS | AI_NONBLOCKING,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };

    for (i = 0; i < NUM_HOSTS; i++) {

        ret = getaddrinfo(hosts[i], PORT, &hints, &addresses[i]);
        switch(ret) {
        case 0:
            pfds[i].fd = -1;
            num_querying -= 1;
            continue;
        
        case EAI_WANT_READ:
            pfds[i].events = POLLIN;
            break;
        
        case EAI_WANT_WRITE:
            pfds[i].events = POLLOUT;
            break;
        
        default:
            exit(1); /* getaddrinfo() returned an error */
        }

        pfds[i].fd = getaddrinfo_fd(hosts[i]);
    }

    while (num_querying > 0) {

        ret = poll(pfds, NUM_HOSTS, -1);
        if (ret < 0)
            exit(1); /* poll() failed */

        for (i = 0; i < NUM_HOSTS; i++) {
            if (pfds[i].revents == 0)
                continue;

            if (pfds[i].revents != POLLIN && pfds[i].revents != POLLOUT)
                exit(1); /* an error occurred on the file descriptor */

            ret = getaddrinfo(hosts[i], PORT, &hints, &addresses[i]);
            switch(ret) {
            case 0:
                pfds[i].fd = -1;
                num_querying -= 1;
                continue;
            
            case EAI_WANT_READ:
                pfds[i].events = POLLIN;
                break;
            
            case EAI_WANT_WRITE:
                pfds[i].events = POLLOUT;
                break;
            
            default:
                exit(1); /* getaddrinfo() returned an error */
            }
        }
    }

    for (i = 0; i < NUM_HOSTS; i++)
        print_addrinfo(addresses[i]);

    /* now all of `addresses` is filled */
}
```

To retrieve the file descriptor associated with an actively-running DNS lookup, 
the following function can be used: 
```c
int getaddrinfo_fd(const char *node);
```
`node` should be the hostname for which the DNS lookup is being performed for. 
The function will return the file descriptor for the DNS lookup, or -1 if 
`node` was not associated with any active DNS lookup. 

Multiple nonblocking `getaddrinfo()` lookups can be performed at the same time; 
however, multiple lookups for the same hostname will all perform one lookup on 
one file descriptor. After the connection and I/O is complete, the lookups will 
return the records requested in the formats specified. For instance, a 
nonblocking lookup that requests IPv4 addresses for `example.com` will utilize 
the same underlying connection as a nonblocking lookup that requests IPv6 
addresses for `example.com`. This saves unnecessary connections and allows for 
easier DNS record caching, but may lead to unexpected behavior for code that 
expects file descriptors to be unique in this case. 

<!--
For a more comprehensive example of an `epoll` server utilizing nonblocking 
DNS resolution alongside nonblocking connections and I/O, see 
[here](../examples/nonblocking.c). 
 -->