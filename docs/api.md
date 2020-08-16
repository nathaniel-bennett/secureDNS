# SecureDNS API

This document gives more detailed information on each API function found 
within `<securedns.h>`.

#

## Table of Contents

[**getaddrinfo**](#getaddrinfo)

[**freeaddrinfo**](#freeaddrinfo)

[**gai_strerror**](#gai_strerror)

[**gai_get_fd**](#gai_get_fd)

[**gai_set_nameserver**](#gai_set_nameserver)

[**gai_nameserver_addr**](#gai_nameserver_addr)

[**gai_nameserver_host**](#gai_nameserver_host)

#


## getaddrinfo
```c
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res);
```

`getaddrinfo` performs two main functions: determining local addresses to 
`bind` to, and performing DNS lookups. The SecureDNS library only applies 
to the second option, so this documentation will only cover the DNS 
resolution capabilities of `getaddrinfo`. Any flags related to finding 
addresses to `bind` to (namely `AI_PASSIVE`, `AI_NUMERICHOST`) will result in 
the `EAI_FLAGS` error if used in conjunction with `AI_TLS`.

When performing DNS lookup, **node** should be passed the hostname to be 
converted into internet addresses and **service** should be passed the port 
that will be connected to. **hints** contains several fields:

- **ai_family**     This field specifies the desired address family for the 
returned addresses. If this is set to `AF_INET` then IPv4 addresses are 
returned; if it is set to `AF_INET6` then IPv6 addresses are returned. 
`AF_UNSPEC` allows for either IPv4 or IPv6 addresses to be returned.
- **ai_socktype**   This field specifies the desired socket type. It may be set 
to `SOCK_STREAM` for stream sockets, `SOCK_DGRAM` for datagram sockets, or 0 if 
socket addresses iwth any protocol can be returned by `getaddrinfo`.
- **ai_protocol**   This field specifies the protocol for the returned socket 
address. It may be set to `IPPROTO_UDP`, `IPPROTO_TCP`, or 0. If set to 0, 
socket addresses with any protocol can be returned by `getaddrinfo`.
- **ai_flags**      This field specifies additional options that are described 
below.

All other fields must contain either 0 or a null pointer, as appropriate.

**ai_flags** can contain any of the following flags:
- `AI_TLS` - Sets the given connection to perform DNS resolution over 
TLS on port 853. 
- `AI_NONBLOCKING` - Sets the given connection to return immediately rather than 
blocking for network data. If this is option is set, either `EAI_WANT_READ` or 
`EAI_WANT_WRITE` will be returned in the event of blocking conditions. In cases 
where the DNS lookup has been previously performed and cached, the 
`getaddrinfo` function may successfully return immediately; programs utilizing 
the nonblocking functionality should account for this possibility. This flag 
only works when used along with `AI_TLS`.
- `AI_CANONNAME` - Sets the given connection to return the canon name of each 
address in the **ai_canonname** field. If this flag is not set, 
**ai_canonname** will be null.
- `AI_NUMERICSERV` - If this flag is specified, then **service** must point to a 
string containing a numeric port number. This inhibits the invocation of name 
resolution, which would convert strings such as "https" automatically to "443".
This is enabled by default when the `AI_TLS` flag is set (i.e. `AI_TLS` is 
functionally the same as `AI_TLS | AI_NUMERICSERV`, so name resolution is 
not supported for DNS over TLS resolution).
- `AI_V4MAPPED` - If this flag is specified, `getaddrinfo` lookups for IPv6 
addresses only (i.e. **hints->ai_family** == `AF_INET6`) will return 
IPv4-mapped IPv6 addresses if no IPv6 addresses could be found for the host.
- `AI_ALL` - If this flag is used along with `AI_V4MAPPED`, lookups for 
IPv6 addresses only will always return IPv4-mapped IPv6 addresses even if IPv6 
addresses could be found for the host. This flag does nothing if `AI_V4MAPPED` 
is not used with it.

The **res** parameter should point to a `struct addrinfo` pointer; it will be 
initialized with a linked list of addrinfo structs. **ai_next** points to the 
next element in the linked list, and the last addrinfo struct will have a value 
of null for its **ai_next** field. The rest of the fields will contain 
information suitable for creating a socket (**ai_family**, **ai_socktype** and 
**ai_protocol**) and connecting it to the desired host (**ai_addr** and 
**ai_addrlen**).

**Parameters**
- \[in\] **node**       The hostname to have DNS resolution performed on.
- \[in\] **service**    The desired port of the host to connect to.
- \[in\] **hints**      An addrinfo struct containing information on what kind 
of connections to return, as well as how to perform the connection (i.e. over 
plaintext or encrypted).
- \[out\] **res**       A linked list of addrinfo structs containing socket 
configurations and addresses suitable for creating sockets with/connecting to.

**Return Value**

`getaddrinfo` returns 0 on success, or one of the following error codes on 
failure:

- **EAI_BADFLAGS** - The flags specified in **hints->ai_flags** were unknown 
or not valid when OR-ed together.

- **EAI_NONAME** - **service** did not contain a known service or a valid port 
number.

- **EAI_AGAIN** - Domain name resolution failed in a non-fatal way; the 
function can be attempted again at a later time. This usually indicates that 
the nameserver is busy.

- **EAI_FAIL** - A non-recoverable failure occurred during name resolution.

- **EAI_NODATA** - No address was associated with the provided hostname in the 
format  specified. This can include hosts that run on IPv4 machines when 
`getaddrinfo` is performed with flags that specify IPv6 only.

- **EAI_FAMILY** - **hints->ai_family** is not a supported family.

- **EAI_SOCKTYPE** - **hints->ai_socktype** is not a supported socket type.

- **EAI_SERVICE** - "Servname not supported for ai_socktype"

- **EAI_ADDRFAMILY** - "Address family for hostname not supported"

- **EAI_MEMORY** - A memory allocation failure occurred while performing the 
request.

- **EAI_SYSTEM** - A system error has occurred. Check **errno** for more 
details.

- **EAI_WANT_READ** - Reading data from the nameserver would result in blocking 
on network resources.

- **EAI_WANT_WRITE** - Writing data to the nameserver would result in blocking 
on network services.

- **EAI_TLS** - An error occurred while performing TLS authentication with the 
nameserver.

#

## freeaddrinfo

```c
void freeaddrinfo(struct addrinfo *res);
```

Frees all a given `addrinfo` structure. Any `addrinfo` 
structs linked to **res** by its `ai_next` field will be freed, as well 
as any internals (such as `ai_addr` and `ai_canonname`).

**Parameters**
- \[in\] **res**        The `addrinfo` structure to be freed.

#

## gai_strerror

```c
const char *gai_strerror(int errcode);
```

Produces a human-readable error string that provides a description of the 
error code returned from `getaddrinfo`. The returned string is statically 
allocated and must not be modified.

**Parameters**
- \[in\] **errcode**    The error code returned by `getaddrinfo`.

 **Return Value**

 `gai_strerror` returns a null-terminated ASCII string that corresponds to 
 **errcode**.

#

## gai_get_fd

```c
int gai_get_fd(const char *node);
```

Retrieves the file descriptor associated with a pending asynchronous DNS over 
TLS lookup. The retrieved file descriptor may be used to wait for the 
nonblocking lookup to be ready for reading/writing via `select`, `poll` 
or some other fd multiplexing function. The file descriptor should not be 
used or modified in any other way than as described above; using `write`, 
`setsockopt`, `fcntl` or some other function on the file descriptor will 
result in undefined behavior. The file descriptor will close automatically 
once the associated DNS lookup has completed or failed, so `close` should not
be used on the file descriptor.

The file descriptor is retrieved based on the hostname passed in to the 
`getaddrinfo` function's **node** parameter. If two different `getaddrinfo` 
system calls attempt to retrieve information for the same hostname (such as 
one looking up IPv4 addresses while the other looks up IPv6 addresses), both 
actually utilize the same underlying connection and so will return the same
file descriptor. All information that can be retrieved for a given hostname 
is queried for, cached, and then converted into the desired output when a 
DNS over TLS request is performed, so two lookups for the same hostname will 
use the same connection until the conversion step.

**Parameters**
- \[in\] **node**       The hostname of the DNS over TLS lookup desired.

**Return Value**

`gai_get_fd` returns the file descriptor used in the asynchronous DNS over TLS 
lookup for **node**, or -1 if no pending lookup could be found for **node**.

#

## gai_set_nameserver

```c
int gai_set_nameserver(in_addr_t addr, const char *hostname);
```

Sets the recursive resolver nameserver that will be connected to when querying 
for/retrieving DNS records. This function only applies to DNS over TLS lookups. 
When the nameserver is set with this function, all nonblocking lookups that 
are in process will be cleared and their file descriptors will be closed. 
Because of this, it is recommended that this function be used before any DNS 
lookups are performed.

**Parameters**
- \[in\] **addr**       The IPv4 address of the nameserver. This must 
be in network byte order.
- \[in\] **hostname**   The hostname of the nameserver. This is required for 
the TLS connection to properly authenticate; if **addr** is not the address of 
**hostname** then this will result in the `EAI_TLS` error.

**Return Value**

`gai_set_nameserver` returns 0 on success, or -1 if **hostname** is null or 
references a string that is greater than 253 characters long.

#

## gai_nameserver_addr

```c
in_addr_t gai_nameserver_addr();
```

Retrieves the address currently being used as the recursive resolver nameserver 
for DNS over TLS lookups.

**Return Value**

`gai_nameserver_addr` returns the IPv4 internet address being connected to for 
DNS over TLS connections. The address is in network byte order.

#

## gai_nameserver_host

```c
const char *gai_nameserver_host();
```

Retrieves the hostname of the recursive resolver server being used for DNS over 
TLS lookups. The returned string is statically allocated and must not be 
modified.

**Return Value**

`gai_nameserver_host` returns a null-terminated ASCII string containing the 
hostname of the nameserver in use.