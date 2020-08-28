cmake_minimum_required(VERSION 3.0)

add_executable(pcap_stats pcap_stats.cc)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall")
include_directories(pcap_stats ${PROJECT_SOURCE_DIR}/bgh ${PROJECT_BINARY_DIR}/bgh)
link_directories(pcap_stats ${PROJECT_SOURCE_DIR})
target_link_libraries(pcap_stats bgh pcap)

