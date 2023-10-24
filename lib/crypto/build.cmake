project(firewall)
cmake_minimum_required(VERSION 3.22)

file(GLOB LIB_SOURCES_CRYPTO ${PROJECT_SOURCE_DIR}/lib/crypto/*.cc)

include_directories(./lib/crypto/)

