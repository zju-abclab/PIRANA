cmake_minimum_required(VERSION 3.13)
project(PIRexamples VERSION 4.0.0 LANGUAGES CXX)

find_package(SEAL 4.0.0 EXACT REQUIRED)
find_package(Kuku 2.1 QUIET REQUIRED)

if(NOT Kuku_FOUND)
    message(FATAL_ERROR "Microsoft Kuku: not found")
else()
    message(STATUS "Microsoft Kuku: found")
endif()
# set(CMAKE_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/../bin)

add_executable(pirexamples)
target_sources(pirexamples
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/main.cc
        ${CMAKE_CURRENT_LIST_DIR}/src/utils.cc
        ${CMAKE_CURRENT_LIST_DIR}/src/pir_parms.cc
        ${CMAKE_CURRENT_LIST_DIR}/src/server.cc
        ${CMAKE_CURRENT_LIST_DIR}/src/client.cc
        ${CMAKE_CURRENT_LIST_DIR}/src/test.cc
)
if(TARGET SEAL::seal)
    target_link_libraries(pirexamples PRIVATE SEAL::seal)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()

target_link_libraries(pirexamples PRIVATE Kuku::kuku)

set_target_properties(pirexamples  PROPERTIES
RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)
