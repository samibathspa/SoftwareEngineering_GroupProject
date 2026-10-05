cmake_minimum_required(VERSION 3.14)
project(PasswordManager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# OpenSSL
find_package(OpenSSL REQUIRED)

# WIN32 marks this as a GUI app (no console window pops up alongside it)
add_executable(password_manager WIN32
    src/main.cpp
    src/crypto.cpp
    src/vault.cpp
)

target_include_directories(password_manager PRIVATE include)
target_link_libraries(password_manager PRIVATE OpenSSL::Crypto)
target_compile_definitions(password_manager PRIVATE UNICODE _UNICODE)

if(WIN32)
    target_link_libraries(password_manager PRIVATE user32 gdi32 comctl32 dwmapi)
    target_link_options(password_manager PRIVATE -municode -static-libgcc -static-libstdc++ -static)
endif()

# Warnings
if(MSVC)
    target_compile_options(password_manager PRIVATE /W4)
else()
    target_compile_options(password_manager PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Install (optional)
install(TARGETS password_manager RUNTIME DESTINATION bin)
