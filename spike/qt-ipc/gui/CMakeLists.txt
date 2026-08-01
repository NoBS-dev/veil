cmake_minimum_required(VERSION 3.24)
project(veil_gui LANGUAGES CXX)

# Note what is absent: no cargo, no cxxbridge include dir, no Rust static lib.
# This build knows nothing about Rust and could be handed to a C++ developer
# who never installs a Rust toolchain.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Quick QuickWidgets Network)

add_executable(veil_gui src/main.cpp)
target_compile_definitions(veil_gui PRIVATE
    QML_PATH="${CMAKE_SOURCE_DIR}/qml/MessageView.qml")
target_link_libraries(veil_gui PRIVATE
    Qt6::Widgets Qt6::Quick Qt6::QuickWidgets Qt6::Network)
