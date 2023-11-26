cmake_minimum_required(VERSION 3.16.0)

set(CMAKE_CXX_STANDARD 17)

project(p11crypto)

#find_package(OpenSSL REQUIRED COMPONENTS ssl crypto)

file(GLOB_RECURSE SRCS CONFIGURE_DEPENDS ./src/*.cpp)

add_library(${PROJECT_NAME} SHARED ${SRCS})
target_link_libraries(${PROJECT_NAME} p11 ssl crypto)
target_include_directories(${PROJECT_NAME} PUBLIC include)
