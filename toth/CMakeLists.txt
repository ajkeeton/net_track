cmake_minimum_required(VERSION 3.0)

add_library(toth toth.c primes.c to.c)
if (UNIX AND NOT APPLE)
    target_link_libraries(toth pthread rt)
else()
    target_link_libraries(toth pthread)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wall -O2")
install(TARGETS toth ARCHIVE DESTINATION /usr/local/lib)
install(FILES toth.h DESTINATION /usr/local/include)
