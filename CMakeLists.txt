# Binary Ninja Anti-Cheat Detector Plugin
cmake_minimum_required(VERSION 3.24)
project(BNAntiCheatDetector CXX)

set(CMAKE_CXX_STANDARD 20)
set(HEADLESS 1)

# Find Binary Ninja API
find_path(BN_API_PATH
    NAMES binaryninjaapi.h
    HINTS ../binaryninja-api binaryninjaapi ../binaryninjaapi
    REQUIRED
)

add_subdirectory(${BN_API_PATH} api)

# Create the plugin library
add_library(BNAntiCheatDetector SHARED
    bn_anticheat_detector.cpp
    bn_plugin.cpp
)

target_link_libraries(BNAntiCheatDetector PUBLIC binaryninjaapi)

# Install the plugin
bn_install_plugin(BNAntiCheatDetector)