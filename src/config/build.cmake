project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB CONFIG_SOURCES ${PROJECT_SOURCE_DIR}/src/config/*.cc)
include_directories(./src/config/)

