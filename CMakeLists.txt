cmake_minimum_required(VERSION 3.16)
project(AntivirusScanner CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_definitions(-DUNICODE -D_UNICODE)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)

add_executable(AntivirusScanner WIN32
    main.cpp
    mainwindow.h
    mainwindow.cpp
)

target_link_libraries(AntivirusScanner PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
)

if(WIN32)
    target_link_libraries(AntivirusScanner PRIVATE shell32 advapi32)
endif()

# Automated deployment post-build rules
add_custom_command(TARGET AntivirusScanner POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/decompile.py"
    "$<TARGET_FILE_DIR:AntivirusScanner>/decompile.py"
    COMMENT "Deploying decompile.py..."
)

add_custom_command(TARGET AntivirusScanner POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    "${CMAKE_CURRENT_SOURCE_DIR}/ghidra"
    "$<TARGET_FILE_DIR:AntivirusScanner>/ghidra"
    COMMENT "Deploying Ghidra directory..."
)