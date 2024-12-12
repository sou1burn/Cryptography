cmake_minimum_required(VERSION 3.10)

project(lab2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")


add_compile_options(-Wall -Wextra -Wpedantic -finput-charset=UTF-8 -fexec-charset=UTF-8)

set(KEY_SOURCES
    Key/Key.cpp
)
add_library(KEY ${KEY_SOURCES})
target_include_directories(KEY PUBLIC Key)


set(FEAL_SOURCES
    FEAL/FEAL.cpp
)
add_library(FEAL ${FEAL_SOURCES})
target_include_directories(FEAL PUBLIC FEAL)
target_link_libraries(FEAL PUBLIC KEY)

set(TESTS_SOURCES
    Tests/Tests.cpp    
)
add_library(TESTS ${TESTS_SOURCES})

set(BMP_SOURCES
    BMP/BMP.cpp
)

add_library(BMP ${BMP_SOURCES})
target_include_directories(BMP PUBLIC BMP)
target_link_libraries(BMP PUBLIC FEAL KEY)

target_include_directories(BMP PUBLIC BMP Tests)

target_include_directories(TESTS PUBLIC Tests)
target_link_libraries(TESTS PUBLIC BMP FEAL KEY)

add_executable(main Main/main.cpp)
target_link_libraries(main PUBLIC BMP FEAL KEY TESTS)
