cmake_minimum_required(VERSION 3.10)

project(lab2) 


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -Wall -Wextra -Wpedantic -finput-charset=UTF-8 -fexec-charset=UTF-8")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(BMP)

set(BMP_SOURCES
    BMP/BMP.cpp
)

add_library(BMP ${BMP_SOURCES})

include_directories(FEAL)

set(FEAL_SOURCES
    FEAL/FEAL.cpp
)

add_library(FEAL ${FEAL_SOURCES})

target_link_libraries(BMP FEAL)

add_executable(main Main/main.cpp)

target_link_libraries(main BMP FEAL)
