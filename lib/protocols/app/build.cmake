project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB LIB_SOURCES_APP ${PROJECT_SOURCE_DIR}/lib/protocols/app/*.cc)

include_directories(./lib/protocols/app/)

