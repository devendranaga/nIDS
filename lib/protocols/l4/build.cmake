project(firewall)
cmake_minimum_required(VERSION 3.25)

file(GLOB LIB_SOURCES_L4 ${PROJECT_SOURCE_DIR}/lib/protocols/l4/*.cc)

include_directories(./lib/protocols/l4/)

