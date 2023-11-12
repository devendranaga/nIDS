project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB FILTER_ETH_SOURCES ${PROJECT_SOURCE_DIR}/src/filters/eth/*.cc)

include_directories(./src/filters/eth/)

