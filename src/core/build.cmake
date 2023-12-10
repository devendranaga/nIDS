project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB CORE_SOURCES ${PROJECT_SOURCE_DIR}/src/core/*.cc)
include_directories(./src/core/)

