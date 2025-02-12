#[[
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

# ethash requires cmake 3.16.2
cmake_minimum_required(VERSION 3.16.2)

option(CONAN_PACKAGE_MANAGER "Use Conan.io as package manager" OFF)

if(CONAN_PACKAGE_MANAGER) # CMAKE CONAN START
  message("Package manager: Conan")

  set(CONAN_BINARY_DIR "${CMAKE_BINARY_DIR}/conan")
  list(APPEND CMAKE_MODULE_PATH ${CONAN_BINARY_DIR})
  list(APPEND CMAKE_PREFIX_PATH ${CONAN_BINARY_DIR})

  if(NOT EXISTS "${CONAN_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/0.18.1/conan.cmake"
         "${CONAN_BINARY_DIR}/conan.cmake" TLS_VERIFY ON
    )
  endif()

  include(${CONAN_BINARY_DIR}/conan.cmake)

  # provide a static conanfile.txt instead of generating it with conan_cmake_configure()
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/conanfile.txt" DESTINATION "${CONAN_BINARY_DIR}")

  if(NOT DEFINED CONAN_PROFILE)
    message(FATAL_ERROR "CONAN_PROFILE is not defined")
  else()
    message(STATUS "CONAN_PROFILE: ${CONAN_PROFILE}")
    conan_cmake_install(
      PATH_OR_REFERENCE "${CONAN_BINARY_DIR}"
      INSTALL_FOLDER "${CONAN_BINARY_DIR}"
      BUILD missing
      PROFILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/profiles/${CONAN_PROFILE}
    )
  endif()
endif() # CMAKE CONAN END

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

get_directory_property(SILKWORM_HAS_PARENT PARENT_DIRECTORY)
if(NOT SILKWORM_HAS_PARENT)
  include(third_party/evmone/cmake/cable/bootstrap.cmake)
  include(CableBuildType)
  cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

  if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain/cxx20.cmake
        CACHE FILEPATH "" FORCE
    )
  endif()

  if(NOT CONAN_PACKAGE_MANAGER)
    set(HUNTER_CONFIG_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/config.cmake")

    include(third_party/evmone/cmake/cable/HunterGate.cmake)
    # https://github.com/cpp-pm/hunter/releases/
    huntergate(
      URL "https://github.com/cpp-pm/hunter/archive/v0.24.15.tar.gz"
      SHA1 "8010d63d5ae611c564889d5fe12d3cb7a45703ac"
      FILEPATH "${HUNTER_CONFIG_PATH}"
    )
  endif()
endif()

project(silkworm)
set(PROJECT_VERSION 0.1.0-dev)

include(CableBuildInfo)

string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${PROJECT_VERSION})
set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})
set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3})

cable_add_buildinfo_library(PROJECT_NAME ${PROJECT_NAME})

option(SILKWORM_WASM_API "Build WebAssembly API" OFF)
option(SILKWORM_CORE_ONLY "Only build Silkworm Core" OFF)
option(SILKWORM_CLANG_COVERAGE "Clang instrumentation for code coverage reports" OFF)
option(SILKWORM_SANITIZE "Build instrumentation for sanitizers" OFF)
option(SILKWORM_USE_MIMALLOC "Enable using mimalloc for dynamic memory management" ON)

get_filename_component(SILKWORM_MAIN_DIR . ABSOLUTE)
set(SILKWORM_MAIN_SRC_DIR "${SILKWORM_MAIN_DIR}/silkworm")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/compiler_settings.cmake)

# Include dependencies handled by Hunter package manager
if(NOT CONAN_PACKAGE_MANAGER)
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/core_packages.cmake)
  if(NOT SILKWORM_CORE_ONLY)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/extra_packages.cmake)
  endif()
endif()

if(NOT SILKWORM_CORE_ONLY)
  # Silence CMake policy warnings in submodules
  set(CMAKE_POLICY_DEFAULT_CMP0048 NEW) # project() command manages VERSION variables
  set(CMAKE_POLICY_DEFAULT_CMP0063 NEW) # Honor visibility properties for all target types

  find_package(Boost REQUIRED)
  # Define Boost::headers target if missing because libtorrent needs it
  if(NOT TARGET Boost::headers)
    add_library(Boost::headers INTERFACE IMPORTED)
    target_include_directories(Boost::headers INTERFACE ${Boost_INCLUDE_DIRS})
  endif()
endif()

add_subdirectory(third_party)

# Compiler enforcements on Silkworm
if(NOT MSVC)
  add_compile_options(-Werror -Wall -Wextra -pedantic)
  add_compile_options(-Wshadow -Wimplicit-fallthrough -Wsign-conversion)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor>)
  add_compile_options(-Wno-missing-field-initializers)

  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-attributes)

    # coroutines support
    if(NOT SILKWORM_WASM_API)
      add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fcoroutines>)
    endif()
  endif()

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_compile_definitions(_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS)
    add_compile_options(-Wthread-safety)
  endif()
endif()

set(SILKWORM_STACK_SIZE 0x1000000)

# Silkworm itself
add_subdirectory(silkworm)

if(NOT SILKWORM_HAS_PARENT)
  add_subdirectory(cmd)
  add_subdirectory(examples)
endif()
