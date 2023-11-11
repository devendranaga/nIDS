project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB FILTER_ETHERTYPE_SOURCES ${PROJECT_SOURCE_DIR}/src/filters/ethertype/*.cc)

include_directories(./src/filters/ethertype/)

