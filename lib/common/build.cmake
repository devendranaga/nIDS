project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB LIB_SOURCES_COMMON ${PROJECT_SOURCE_DIR}/lib/common/*.cc)

include_directories(./lib/common/)

