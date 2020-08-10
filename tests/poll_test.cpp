extern "C" {


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>
#include <netdb.h>
#include "../include/securedns.h"

#define NUM_HOSTS 6
#define PORT "80"

const char *hosts[NUM_HOSTS] = {"example1.com", "example2.com", "example3.com"
                                "example4.com", "example5.com", "example6.com"};


void print_addrinfo(struct addrinfo *info);


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

/*
int main(int argc, char **argv) {

    struct addrinfo hints = {0};
    struct addrinfo *res;
    int ret;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_TLS | AI_NONBLOCKING;

    pollfd pfd;

    do {
        printf("still going...\n");

        ret = getaddrinfo(HOST, PORT, &hints, &res);
        if (ret != EAI_WANT_WRITE && ret != EAI_WANT_READ)
            break;

        if (ret == EAI_WANT_READ)
            pfd.events = POLLIN;
        else
            pfd.events = POLLOUT;

        pfd.fd = getaddrinfo_fd(HOST);
        if (pfd.fd == -1) {
            printf("getaddrinfo_fd failed\n");
            exit(1);
        }

        int poll_ret = poll(&pfd, 1, 5000);
        if (poll_ret <= 0) {
            printf("poll_ret returned <= 0\n");
            exit(1);
        }
    } while (ret < 0);

    if (ret < 0) {
        printf("getaddrinfo failed with code %i: %s\n",
               ret, gai_strerror(ret));
        if (ret == EAI_SYSTEM)
            perror("EAI_SYSTEM errno");
        return 1;
    }

    print_addrinfo(res);

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("Socket failed");
        return 1;
    }

    ret = connect(sock, res->ai_addr, res->ai_addrlen);
    if (ret < 0) {
        perror("Connect failed");
        return 1;
    }

    const char *msg = "GET / HTTP/1.1\r\n\r\n";
    ret = send(sock, msg, strlen(msg), 0);
    if (ret < 0)
        perror("send");
    if (ret < strlen(msg))
        printf("Send didn't send all info\n");

    char buf[1000] = {0};
    ret = recv(sock, buf, 1000, 0);
    if (ret < 0)
        perror("recv");
    if (ret == 0)
        printf("peer closed connection\n");

    printf("Received: %s\n", buf);

    close(sock);

    freeaddrinfo(res);
    return 0;
}

*/

void print_addrinfo(struct addrinfo *info) {
    int i;

    printf("ai_family: ");
    if (info->ai_family == AF_INET)
        printf("AF_INET\n");
    else if (info->ai_family == AF_INET6)
        printf("AF_INET6\n");
    else
        printf("unknown (%i)\n", info->ai_family);

    printf("ai_socktype: ");
    if (info->ai_socktype == SOCK_STREAM)
        printf("SOCK_STREAM\n");
    else if (info->ai_socktype == SOCK_DGRAM)
        printf("SOCK_DGRAM\n");
    else if (info->ai_socktype == SOCK_RAW)
        printf("SOCK_RAW\n");
    else
        printf("unknown (%i)\n", info->ai_socktype);

    printf("ai_protocol: ");
    if (info->ai_protocol == IPPROTO_TCP)
        printf("IPPROTO_TCP\n");
    else if (info->ai_protocol == IPPROTO_UDP)
        printf("IPPROTO_UDP\n");
    else if (info->ai_protocol == 0)
        printf("<no protocol>\n");
    else
        printf("unknown (%i)\n", info->ai_protocol);

    printf("ai_canonname: %s\n",
           info->ai_canonname ? info->ai_canonname : "NULL");

    printf("ai_addrlen: %i\n", info->ai_addrlen);

    printf("ai_addr: \n");
    if (info->ai_addr->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*) info->ai_addr;

        printf("  addr->sa_family: AF_INET\n");
        printf("  addr->sin_port: %i\n", ntohs(addr->sin_port));
        printf("  addr->sin_addr: %x\n", ntohl(addr->sin_addr.s_addr));
    } else if (info->ai_addr->sa_family == AF_INET6) {
        struct sockaddr_in6* addr = (struct sockaddr_in6*) info->ai_addr;
        printf("  addr->sa_family: AF_INET6\n");
        printf("  addr->sin6_port: %i\n", ntohs(addr->sin6_port));
        printf("  addr->sin6_addr: ");
        for (i = 0; i < 16; i++)
            printf("%x ", ((unsigned char*) addr->sin6_addr.s6_addr)[i]);
        printf("\n");

    } else {
        printf("unknown address family: %i\n", info->ai_addr->sa_family);
    }



    printf("ai_next: ");
    if (info->ai_next != NULL) {
        printf("\n\n");
        print_addrinfo(info->ai_next);
    } else {
        printf("NULL\n\n");
    }
}

}

