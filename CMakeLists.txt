cmake_minimum_required(VERSION 3.16)
project(securedns C)
set(CMAKE_C_STANDARD 90)

set(CMAKE_C_FLAGS "-D_GNU_SOURCE")

link_libraries("ssl" "crypto")

add_library(securedns
        include/securedns.h
        src/wrapper_dns.c
        src/original_dns.c
        src/original_dns.h
        src/saved_contexts.c
        src/saved_contexts.h
        src/records_cache.c 
        src/records_cache.h 
        src/dns_context.c 
        src/dns_context.h 
        src/resource_records.c 
        src/resource_records.h 
        src/addrinfo.c 
        src/addrinfo.h 
        src/str_hashmap.c 
        src/str_hashmap.h)

add_executable(simple_test
        tests/simple_test.c
        include/securedns.h)
target_link_libraries(simple_test "securedns")

add_executable(async_test
        tests/async_test.c
        include/securedns.h)
target_link_libraries(async_test "securedns")

add_executable(poll_test
        tests/poll_test.c
        include/securedns.h)
target_link_libraries(poll_test "securedns")
