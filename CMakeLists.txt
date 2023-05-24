cmake_minimum_required(VERSION 3.0.0)
project(ysda-networks-tls VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)

include(CTest)
enable_testing()

add_executable(tls_client main.cpp)

find_package(cxxopts REQUIRED)
target_link_libraries(tls_client cxxopts::cxxopts)

find_package(OpenSSL 1.1.1 REQUIRED)
target_link_libraries(tls_client OpenSSL::Crypto)
target_link_libraries(tls_client OpenSSL::SSL)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
