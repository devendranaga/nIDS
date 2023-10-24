project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB LIB_SOURCES_L3 ${PROJECT_SOURCE_DIR}/lib/protocols/l3/*.cc)

include_directories(./lib/protocols/l3/)

