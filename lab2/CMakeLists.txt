cmake_minimum_required(VERSION 3.10)

project(lab2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -Wall -Wextra -Wpedantic -finput-charset=UTF-8 -fexec-charset=UTF-8")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(Key)
include_directories(FEAL)
include_directories(BMP)

set(TESTS_SOURCES
    Tests/Tests.cpp    
)

#add_library(TESTS ${TESTS_SOURCES})

set(KEY_SOURCES
    Key/Key.cpp
)

add_library(KEY ${KEY_SOURCES})

set(FEAL_SOURCES
    FEAL/FEAL.cpp
)

add_library(FEAL ${FEAL_SOURCES})


target_link_libraries(FEAL PUBLIC KEY)

set(BMP_SOURCES
    BMP/BMP.cpp
)
add_library(BMP ${BMP_SOURCES})

target_link_libraries(BMP PUBLIC FEAL KEY)

add_executable(main Main/main.cpp)

target_link_libraries(main BMP FEAL KEY)
