cmake_minimum_required(VERSION 3.10)

project(lab4 VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
add_definitions(${PCAP_CFLAGS_OTHER})

add_compile_options(-Wall -Wextra -Wpedantic -finput-charset=UTF-8 -fexec-charset=UTF-8)
include_directories(src/md5)

set(MD5_SOURCES src/md5/md5hash.cpp)
    
add_library(MD5 ${MD5_SOURCES})
target_include_directories(MD5 PUBLIC MD5)

add_executable(main src/main.cpp)

target_link_libraries(main PUBLIC MD5)
