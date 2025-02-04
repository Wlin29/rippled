cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()
if(POLICY CMP0077)
  cmake_policy(SET CMP0077 NEW)
endif()

# Fix "unrecognized escape" issues when passing CMAKE_MODULE_PATH on Windows.
file(TO_CMAKE_PATH "${CMAKE_MODULE_PATH}" CMAKE_MODULE_PATH)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

project(xrpl)
# Had to downgrade to cpp 11 to avoid errors	
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(
  CURVE
  "BN128"
  CACHE
  STRING
  "Default curve: one of ALT_BN128, BN128, EDWARDS, MNT4, MNT6"
)

set(
  OPT_FLAGS
  ""
  CACHE
  STRING
  "Override C++ compiler optimization flags"
)

option(
  MULTICORE
  "Enable parallelized execution, using OpenMP"
  OFF
)

option(
  WITH_PROCPS
  "Use procps for memory profiling"
  ON
)

option(
  VERBOSE
  "Print internal messages"
  OFF
)

# Conditionally define preprocessor macros based on the CURVE variable
if(${CURVE} STREQUAL "ALT_BN128")
  add_definitions(-DCURVE_ALT_BN128)
elseif(${CURVE} STREQUAL "BN128")
  add_definitions(-DCURVE_BN128)
elseif(${CURVE} STREQUAL "EDWARDS")
  add_definitions(-DCURVE_EDWARDS)
elseif(${CURVE} STREQUAL "MNT4")
  add_definitions(-DCURVE_MNT4)
elseif(${CURVE} STREQUAL "MNT6")
  add_definitions(-DCURVE_MNT6)
else()
  message(FATAL_ERROR "Unknown curve: ${CURVE}")
endif()

# make GIT_COMMIT_HASH define available to all sources
find_package(Git)
if(Git_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=${CMAKE_CURRENT_SOURCE_DIR}/.git describe --always --abbrev=40
        OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE gch)
    if(gch)
        set(GIT_COMMIT_HASH "${gch}")
        message(STATUS gch: ${GIT_COMMIT_HASH})
        add_definitions(-DGIT_COMMIT_HASH="${GIT_COMMIT_HASH}")
    endif()
endif() #git

if(thread_safety_analysis)
  add_compile_options(-Wthread-safety -D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS -DRIPPLE_ENABLE_THREAD_SAFETY_ANNOTATIONS)
  add_compile_options("-stdlib=libc++")
  add_link_options("-stdlib=libc++")
endif()

include (CheckCXXCompilerFlag)
include (FetchContent)
include (ExternalProject)
include (CMakeFuncs)

if (target)
  message (FATAL_ERROR "The target option has been removed - use native cmake options to control build")
endif ()

include(RippledSanity)
include(RippledVersion)
include(RippledSettings)

if (packages_only)
  if (NOT TARGET rpm)
    message (FATAL_ERROR "packages_only requested, but targets were not created - is docker installed?")
  endif()
  return ()
endif ()

include(RippledCompiler)
include(RippledInterface)
option(only_docs "Include only the docs target?" FALSE)
include(RippledDocs)

if(only_docs)
  return()
endif()

include(deps/Boost)
set(SECP256K1_INSTALL TRUE)
add_subdirectory(external/secp256k1)
add_library(secp256k1::secp256k1 ALIAS secp256k1)
add_subdirectory(external/ed25519-donna)
add_subdirectory(external/antithesis-sdk)

find_package(gRPC REQUIRED)
find_package(lz4 REQUIRED)
find_package(LibArchive REQUIRED)
find_package(SOCI REQUIRED)
find_package(SQLite3 REQUIRED)

option(rocksdb "Enable RocksDB" ON)
if(rocksdb)
  find_package(RocksDB REQUIRED)
  set_target_properties(RocksDB::rocksdb PROPERTIES
    INTERFACE_COMPILE_DEFINITIONS RIPPLE_ROCKSDB_AVAILABLE=1
  )
  target_link_libraries(ripple_libs INTERFACE RocksDB::rocksdb)
endif()

find_package(nudb REQUIRED)
find_package(date REQUIRED)
find_package(xxHash REQUIRED)

# Add LibSNARK dependencies first
find_package(OpenSSL REQUIRED)
find_package(GMP REQUIRED)

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/external/libsnark/CMakeLists.txt)
  message(FATAL_ERROR "LibSNARK submodule not found. Please run: git submodule update --init --recursive")
endif()
# Add libsnark as a subdirectory
add_subdirectory(${CMAKE_SOURCE_DIR}/external/libsnark)

# Include directories for libsnark and its dependencies
include_directories(${CMAKE_SOURCE_DIR}/external/libsnark)
include_directories(${CMAKE_SOURCE_DIR}/external/libsnark/depends/libff)
include_directories(${CMAKE_SOURCE_DIR}/external/libsnark/depends/libfqfft)

# Link directories for libsnark and its dependencies
link_directories(${CMAKE_SOURCE_DIR}/external/libsnark/build/libsnark)
link_directories(${CMAKE_SOURCE_DIR}/external/libsnark/depends/libff/build/libff)

# Update ripple_libs to include libsnark
target_link_libraries(ripple_libs INTERFACE
  ed25519::ed25519
  lz4::lz4
  OpenSSL::Crypto
  OpenSSL::SSL
  secp256k1::secp256k1
  soci::soci
  SQLite::SQLite3
  snark
  snark_adsnark
  gmp
  gmpxx
)

if(TARGET nudb::core)
  set(nudb nudb::core)
elseif(TARGET NuDB::nudb)
  set(nudb NuDB::nudb)
else()
  message(FATAL_ERROR "unknown nudb target")
endif()
target_link_libraries(ripple_libs INTERFACE ${nudb})

if(coverage)
  include(RippledCov)
endif()

set(PROJECT_EXPORT_SET RippleExports)
include(RippledCore)
include(RippledInstall)
include(RippledValidatorKeys)

# include_directories(${CMAKE_SOURCE_DIR}/external/libsnark/include)

add_executable(test_libsnark ./include/xrpl/protocol/zk/ZkPrivateKeyCircuit.cpp)
target_link_libraries(test_libsnark snark snark_adsnark gmp gmpxx)

# cd .build
# make
# make test_libsnark
# ./test_libsnark	