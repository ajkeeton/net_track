cmake_minimum_required(VERSION 3.0)

add_executable(test_bgh test_bgh.cc)

include_directories(test_bgh ${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})
link_directories(test_bgh ${PROJECT_SOURCE_DIR})
target_link_libraries(test_bgh bgh)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11")
