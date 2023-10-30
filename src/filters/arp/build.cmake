project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB FILTER_ARP_SOURCES ${PROJECT_SOURCE_DIR}/src/filters/arp/*.cc)

include_directories(./src/filters/arp/)

