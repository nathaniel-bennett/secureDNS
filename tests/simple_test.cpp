extern "C" {

#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "../include/dns.h"

    void print_addrinfo(struct addrinfo *info);

    int main(int argc, char **argv) {

        struct addrinfo hints = {0};
        struct addrinfo *res;
        int ret;

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_TLS;

        ret = getaddrinfo("deccio.byu.edu", "80", &hints, &res);
        if (ret != 0) {
            printf("getaddrinfo failed with code %i: %s\n",
                        ret, gai_strerror(ret));
            if (ret == EAI_SYSTEM)
                perror("EAI_SYSTEM errno");
            return 1;
        }

        print_addrinfo(res);
        freeaddrinfo(res);

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = 0;

        ret = getaddrinfo("intel.com", "80", &hints, &res);
        if (ret != 0) {
            printf("getaddrinfo failed with code %i: %s\n",
                   ret, gai_strerror(ret));
            if (ret == EAI_SYSTEM)
                perror("EAI_SYSTEM errno");
            return 1;
        }

        print_addrinfo(res);
        freeaddrinfo(res);


        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = 0;

        ret = getaddrinfo("google.com", "80", &hints, &res);
        if (ret != 0) {
            printf("getaddrinfo failed with code %i: %s\n",
                   ret, gai_strerror(ret));
            if (ret == EAI_SYSTEM)
                perror("EAI_SYSTEM errno");
            return 1;
        }

        print_addrinfo(res);
        freeaddrinfo(res);


        /*
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
         */

        return 0;
    }

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
