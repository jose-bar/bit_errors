cmake_minimum_required(VERSION 3.5)

project(MyOpenFHEProject)

find_package(OpenFHE REQUIRED)

message(STATUS "OpenFHE Found at: ${OpenFHE_DIR}")

include_directories(
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
)

set(BLAKE3_SOURCES 
    BLAKE3/c/blake3.c
    BLAKE3/c/blake3_dispatch.c
    BLAKE3/c/blake3_portable.c
    BLAKE3/c/blake3_sse2.c
    BLAKE3/c/blake3_sse41.c
    BLAKE3/c/blake3_avx2.c
    BLAKE3/c/blake3_avx512.c
)

set_source_files_properties(BLAKE3/c/blake3_sse2.c PROPERTIES COMPILE_FLAGS "-msse2")
set_source_files_properties(BLAKE3/c/blake3_sse41.c PROPERTIES COMPILE_FLAGS "-msse4.1")
set_source_files_properties(BLAKE3/c/blake3_avx2.c PROPERTIES COMPILE_FLAGS "-mavx2")
set_source_files_properties(BLAKE3/c/blake3_avx512.c PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512vl")

add_executable(global_hash global_hash.cpp ${BLAKE3_SOURCES})
target_include_directories(global_hash PRIVATE BLAKE3/c)
target_link_libraries(global_hash ${OpenFHE_LIBRARIES})

add_executable(flat_chunked flat_chunked.cpp ${BLAKE3_SOURCES})
target_include_directories(flat_chunked PRIVATE BLAKE3/c)
target_link_libraries(flat_chunked ${OpenFHE_LIBRARIES})

add_executable(hash_ecc hash_ecc.cpp ${BLAKE3_SOURCES})
target_include_directories(hash_ecc PRIVATE BLAKE3/c)
target_include_directories(hash_ecc PRIVATE Reed-Solomon/include)
target_link_libraries(hash_ecc ${OpenFHE_LIBRARIES})

add_executable(merkle_tree merkle_tree.cpp ${BLAKE3_SOURCES})
target_include_directories(merkle_tree PRIVATE BLAKE3/c)
target_link_libraries(merkle_tree ${OpenFHE_LIBRARIES})

set_target_properties(global_hash PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)