cmake_minimum_required(VERSION 3.0)

add_library(bgh bgh.c primes.c)
target_link_libraries(bgh pthread rt)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -fPIC -g -Wall -O2")
