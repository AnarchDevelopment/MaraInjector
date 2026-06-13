cmake_minimum_required(VERSION 3.10)
project(MaraInjector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force Unicode
add_definitions(-DUNICODE -D_UNICODE)

add_executable(mara mara.cpp)

# Link against common Windows libraries
target_link_libraries(mara kernel32 user32 shell32 advapi32 Aclapi)

set_target_properties(mara PROPERTIES 
    OUTPUT_NAME "mara"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
