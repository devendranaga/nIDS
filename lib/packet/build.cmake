project(firewall)
cmake_minimum_required(VERSION 3.25)

file(GLOB LIB_SOURCES_PACKET ${PROJECT_SOURCE_DIR}/lib/packet/*.cc)

include_directories(./lib/packet/)
