cmake_minimum_required(VERSION 3.0)

add_library(llto llto.c ../bgh/primes.c)
if (UNIX AND NOT APPLE)
    target_link_libraries(llto pthread rt)
else()
    target_link_libraries(llto pthread)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/bgh
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ibgh -fPIC -Wall -O0 -g")
install(TARGETS llto ARCHIVE DESTINATION /usr/local/lib)
install(FILES llto.h DESTINATION /usr/local/include)
