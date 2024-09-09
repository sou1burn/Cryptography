cmake_minimum_required(VERSION 3.10)

project(lab1 VERSION 0.1) 


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -Wall -Wextra -Wpedantic -finput-charset=UTF-8 -fexec-charset=UTF-8")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


set(SOURCE_FILES
    main.cpp
    funcs.cpp
    funcs.h
    )



add_executable(lab1 ${SOURCE_FILES})


