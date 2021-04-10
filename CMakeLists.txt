cmake_minimum_required(VERSION "3.10.2")


project("AntiDetectionTechniques" C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(EXECUTABLE_NAME anti_techniques)

include_directories(${PROJECT_SOURCE_DIR})
add_executable(${EXECUTABLE_NAME} util.cpp test_sandbox_presence.cpp test_vm_presence.cpp test_auto_analysis.cpp anti_vm.cpp)
target_link_libraries(${EXECUTABLE_NAME} stdc++fs)
