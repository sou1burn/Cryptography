cmake_minimum_required(VERSION 3.0)
project(lab6)

set(CMAKE_CXX_STANDARD 14)
include_directories(src)

set(SCNHORR_SOURCES src/SchnorrScheme.cpp)

add_library(SCNHORR ${SCNHORR_SOURCES})
target_include_directories(SCNHORR PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

find_package(OpenSSL REQUIRED)
add_executable(lab6 main.cpp)

target_link_libraries(SCNHORR PRIVATE OpenSSL::Crypto)
target_link_libraries(lab6 PUBLIC SCNHORR)