cmake_minimum_required(VERSION 3.16)
project(securedns C CXX)


set(CMAKE_C_STANDARD 90)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_C_FLAGS "-D_GNU_SOURCE")

link_libraries("ssl" "crypto")

add_library(securedns
        include/dns.h
        src/wrapper_dns.c
        src/original_dns.c
        src/original_dns.h
        src/dns_hashmap.c
        src/dns_hashmap.h src/cache.c src/cache.h src/dns_context.c src/dns_context.h src/resource_records.c src/resource_records.h src/addrinfo.c src/addrinfo.h)

add_executable(simple_test
        tests/simple_test.cpp include/dns.h)


target_link_libraries(simple_test "securedns")