cmake_minimum_required(VERSION 3.10)
project(dns_proxy C)

set(CMAKE_C_STANDARD 99)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/external/tomlc17/src
)

add_executable(dns_proxy
    src/main.c
    src/toml_parser.c
    src/dns_parser.c
    external/tomlc17/src/tomlc17.c
)

configure_file(config/config.toml config.toml COPYONLY)