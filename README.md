# SecureDNS - Transparent wrapper of the `getaddrinfo` function for DNS over TLS

The SecureDNS library is a lightweight stub resolver implementation that 
implements DNS over TLS (DoT). It is fully compatible with ANSI C, and only 
requires linking with OpenSSL's `libssl` and `libcrypto` libraries to work. 
It utilizes the OpenSSL library to establish a TLS connection with a DNS 
server of the user's choice (the default is Cloudflare's 1.1.1.1 DNS resolver) 
and send safely encrypted DNS queries.

The API for the SecureDNS stub resolver wraps around the `getaddrinfo()` DNS 
resolution function found in `<netdb.h>`, leaving all existing functionality 
unchanged while adding two simple flags: `AI_TLS` and `AI_NONBLOCKING`. 
Similarly, the `freeaddrinfo()` function is wrapped by the SecureDNS library, 
though this is simply to free up a few internals introduced by the SecureDNS 
library. A couple other new functions are added (one to better facilitate 
non-blocking DNS resolution with multiplexing functions like `poll()` or 
`select()`, and another to specify the DoT recursive resolver server to 
connect to for DNS over TLS resolution), but the library is kept 
as simple as possible to allow for easy adoption in a wide variety of new 
or existing C/C++ projects.

For information on installing see [here](docs/install.md).

# Project Status

This library is being actively worked on and tested. There are no planned 
changes that would break the API or any existing functionality. Polling 
is fully functional, and there are no known memory 
leaks or or implementation breaks based on current testing. It should be 
noted, however, that this project is in Beta stage development--it should not 
be relied on for any critical systems.

### Current Features
 - DNS over TLS (DoT) lookup using TLS 1.3 and strong default ciphers
 - IPv4 and IPv6 both supported
 - Asynchronous DNS resolution
 - Can handle an arbitrary number of asynchronous DNS queries at the same time 
 - In-memory DNS record caching/reuse that conforms to record TTL constraints 
 - TLS session caching and resumption to significantly improve handshake speed 
 - Ability to set a custom recursive resolver address to use for DNS lookups 
 
### Features to be Added Soon
 - A slew of tests
 - Integration into the SecureSockets Library
 
### Features for Later
 - Automatic installation
 - MacOS, Windows & BSD support
 - Automatic switching to a backup server when connections with the main 
 server fail 
 - DNS over HTTPS
 - Support for other SSL libraries (maybe...)
 
# Using the Library
The SecureDNS library was designed to be as similar to the existing 
`getaddrinfo()` implementation of DNS; because of this, refactoring legacy 
code to use DNS over TLS becomes as easy as adding `#include <securedns.h>` 
to the top of the file and adding `AI_TLS` to the addrinfo flags added to 
`hints`. The example code below highlights the simplicity of this change:
 
 ```c
#include <netdb.h> /* Note that netdb can be included--it won't break anything */
#include <securedns.h> /* <-- library included */

int main(int argc, char *argv[]) {
    
    struct addrinfo *result;

    struct addrinfo hints = {
        .ai_family = AF_INET6,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_NUMERICSERV | AI_TLS, /* <-- `AI_TLS` added to hints */
    };

    int ret = getaddrinfo("nathanielbennett.com", "443", &hints, &result); 
    /* ^ no change needed for the function call; runs DNS over TLS transparently */
    if (ret != 0)
        exit(1);
    
    /* TODO: create socket here, connect to host, and so on */
}
```
 
In addition to the traditional use cases of `getaddrinfo()`, the SecureDNS 
library gives users the ability to perform DNS lookups asynchronously through 
the use of the `AI_NONBLOCKING` flag and the `getaddrinfo_fd()` function. When 
the `AI_NONBLOCKING` flag is set in `hints`,  the resulting `getaddrinfo()` 
function call will return with either `EAI_WANT_READ` or `EAI_WANT_WRITE` when 
the DNS lookup would block on reading or writing/connecting, respectively. 
Subsequent calls to `getaddrinfo()` that have the same hostname passed into 
`node` will result in one of these two error codes until the stub resolver has 
fully completed the DNS resolution (or until an error occurs).

In situations where `poll()`, `select()` or some other file descriptor 
multiplexing function is used, `getaddrinfo_fd()` may be used to retrieve the 
internal file descriptor being used for the DNS lookup. The returned file 
descriptor can be passed into one of these functions in the appropriate 
place to asynchronously complete a DNS resolution. 

Take `select()`, for instance. 

```c
#include <sys/select.h>

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout);
```
to use `select()`, the file descriptor of the DNS resolution would be put 
into the `readfds` set if `EAI_WANT_READ` was the returned value from 
`getaddrinfo()`, or the `writefds` set if `EAI_WANT_WRITE` was returned.
Since `getaddrinfo()` may return `EAI_WANT_READ` or `EAI_WANT_WRITE` 
multiple times when being polled, the file descriptor **needs** to be 
moved from `writefds` to `readfds` and vice versa if the return value 
of `getaddrinfo()` changes.

The same would go for `poll()`--the main difference is that `POLLIN` 
would be used when `EAI_WANT_READ` is returned and `POLLOUT` would be 
used when `EAI_WANT_WRITE is returned`.

Further documentation will be added sometime soon.
 
 
 
 
 
 
 
 
 
