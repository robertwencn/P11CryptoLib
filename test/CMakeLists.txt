cmake_minimum_required(VERSION 3.16.0)

set(CMAKE_CXX_STANDARD 17)

project(p11crypto_test)

find_package(OpenSSL REQUIRED)
#find_package(gtest REQUIRED)
#find_package(libp11 REQUIRED)

file(GLOB_RECURSE TEST_SRC CONFIGURE_DEPENDS src/*.cpp)
file(GLOB_RECURSE TARGET_SRC CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../src/*.cpp)

add_executable(${PROJECT_NAME} src/main.cpp ${TEST_SRC} ${TARGET_SRC})
target_link_libraries(${PROJECT_NAME} PUBLIC ssl crypto p11 gtest pthread)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)