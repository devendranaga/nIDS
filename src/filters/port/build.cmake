project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB FILTER_PORT_SOURCES ${PROJECT_SOURCE_DIR}/src/filters/port/*.cc)

include_directories(./src/filters/port/)

