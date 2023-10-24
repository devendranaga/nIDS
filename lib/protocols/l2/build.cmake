project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB LIB_SOURCES_L2 ${PROJECT_SOURCE_DIR}/lib/protocols/l2/*.cc)

include_directories(./lib/protocols/l2/)

