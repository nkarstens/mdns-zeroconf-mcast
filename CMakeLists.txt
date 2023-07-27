cmake_minimum_required(VERSION 3.10)

project(mdns-zeroconf-mcast
    VERSION 1.0.0
    LANGUAGES C
    DESCRIPTION "mDNS-Based Zero-Configuration Multicast Address Allocation"
)

# Locate required libraries
find_package(PkgConfig REQUIRED)

pkg_check_modules(AVAHI-CLIENT REQUIRED IMPORTED_TARGET avahi-client)

add_executable(
    mdns-zeroconf-mcast
    mdns-zeroconf-mcast.c
)

target_link_libraries(
    mdns-zeroconf-mcast
    PkgConfig::AVAHI-CLIENT
)