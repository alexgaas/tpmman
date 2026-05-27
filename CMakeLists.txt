cmake_minimum_required(VERSION 4.0)
project(tpmman)

set(CMAKE_CXX_STANDARD 20)

find_package(yaml-cpp REQUIRED)
find_package(Poco REQUIRED Foundation)

add_library(tpmman SHARED
        src/pkcs11/pkcs11.cpp
        src/pkcs11/pkcs11.h
        src/tpm/tpm.h
        src/tpm/tpm.cpp
        src/util/logger.h
        src/util/logger.cpp
        src/config/config.h
        src/config/config.cpp
)

target_link_libraries(tpmman PRIVATE
    yaml-cpp::yaml-cpp
    Poco::Foundation
)

add_executable(tpmman_cli
        src/main/main.cpp
        src/util/logger.h
        src/util/logger.cpp
        src/config/config.h
        src/config/config.cpp
)

target_link_libraries(tpmman_cli PRIVATE 
    yaml-cpp::yaml-cpp
    Poco::Foundation
)
