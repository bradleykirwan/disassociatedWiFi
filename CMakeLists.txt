cmake_minimum_required(VERSION 3.6)
project(untitled)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(MAIN_SOURCE_FILES main.cpp mac.cpp mac.h radiotap.h radiotap.cpp ieee80211_radiotap.h)
add_executable(main ${MAIN_SOURCE_FILES})
target_link_libraries(main pcap)

set(TEST_SOURCE_FILES test.cpp)
add_executable(tester ${TEST_SOURCE_FILES})