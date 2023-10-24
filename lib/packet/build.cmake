project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB LIB_SOURCES_PACKET ${PROJECT_SOURCE_DIR}/lib/packet/*.cc)

include_directories(./lib/packet/)

