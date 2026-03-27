cmake_minimum_required(VERSION 3.20)
project(crystals_ffi LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)

find_package(Crystals REQUIRED HINTS /usr/local/lib/cmake/crystals)
find_package(OpenSSL REQUIRED)

add_library(crystals_ffi STATIC src/crystals_ffi.cpp)
target_include_directories(crystals_ffi PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(crystals_ffi PRIVATE Crystals::crystals OpenSSL::Crypto)

add_executable(test_shim test/test_shim.c)
target_link_libraries(test_shim PRIVATE crystals_ffi)
target_include_directories(test_shim PRIVATE include)
