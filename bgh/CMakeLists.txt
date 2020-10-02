cmake_minimum_required(VERSION 3.0)

add_library(bgh bgh.c primes.c)
if (UNIX AND NOT APPLE)
    target_link_libraries(bgh pthread rt)
else()
    target_link_libraries(bgh pthread)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -fPIC -Wall -O2")
install(TARGETS bgh ARCHIVE DESTINATION /usr/local/lib)
install(FILES bgh.h DESTINATION /usr/local/include)
