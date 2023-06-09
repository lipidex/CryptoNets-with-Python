cmake_minimum_required(VERSION 3.13)

project(SEALExamples VERSION 4.1.1 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_EXAMPLES)
    set(SEAL_BUILD_EXAMPLES ON)

    # Import Microsoft SEAL
    find_package(SEAL 4.1.1 EXACT REQUIRED)

    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/../lib/wrapper)
endif()

if(SEAL_BUILD_EXAMPLES)
    add_library(sealwrapper SHARED)

    target_sources(sealwrapper
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/wrapper.cpp
    )

    if(TARGET SEAL::seal)
        target_link_libraries(sealwrapper PUBLIC SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(sealwrapper PUBLIC SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
