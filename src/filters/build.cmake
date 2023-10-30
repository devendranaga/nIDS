project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB FILTER_SOURCES ${PROJECT_SOURCE_DIR}/src/filters/*.cc)

include_directories(./src/filters/)

