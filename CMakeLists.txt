cmake_minimum_required(VERSION 3.16)
project(securedns C CXX)


set(CMAKE_C_STANDARD 90)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_C_FLAGS "-D_GNU_SOURCE")

link_libraries("ssl" "crypto")

add_library(securedns
        dns.h
        wrapper_dns.c
        original_dns.c
        original_dns.h
        dns_hashmap.c
        dns_hashmap.h dns_cache.c dns_cache.h dns_context.c dns_context.h resource_records.c resource_records.h addrinfo.c addrinfo.h)

add_executable(simple_test
        simple_test.cpp dns.h)


target_link_libraries(simple_test "securedns")