cmake_minimum_required(VERSION 3.10)
project(CryptoFile VERSION 1.0)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${PROJECT_SOURCE_DIR}/ws)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

# Add source files
add_executable(crypto_app src/main.cpp src/CryptoFile.cpp)

# Link against OpenSSL
target_link_libraries(crypto_app ${OPENSSL_LIBRARIES})