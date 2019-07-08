cmake_minimum_required(VERSION 3.14)
project(art_learning)
set(CMAKE_CXX_STANDARD 14)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost COMPONENTS log log_setup thread filesystem system)
if (!Boost_FOUND)
    message(FATAL_ERROR "Boost Not Find")
endif ()
include_directories( ${Boost_INCLUDE_DIR} )

set(src_files
        base/base.h
        base/base.cpp
        dex/DexFile.cpp
        dex/DexFile.h
        )

add_executable(dexdump ${src_files} dexdump/main.cpp)
TARGET_LINK_LIBRARIES( dexdump
        ${Boost_LOG_SETUP_LIBRARY}
        ${Boost_LOG_LIBRARY}
        ${Boost_FILESYSTEM_LIBRARY}
        ${Boost_THREAD_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        )