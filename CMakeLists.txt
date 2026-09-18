#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.10)
project(nxpsc VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(NXPSC_BUILD_SHARED "Build the shared library" ON)
option(NXPSC_BUILD_TESTS "Build the test suite" ON)
option(NXPSC_BUILD_EXAMPLES "Build the examples" ON)

set(NXPSC_SOURCES
    src/nxpsc_core.c
    src/nxpsc_crypto.c
    src/nxpsc_channel.c
    src/nxpsc_desfire.c
    src/nxpsc_advanced.c
    src/nxpsc_ntag424.c
    src/nxpsc_plus.c
    src/nxpsc_selftest.c
)

# minimal mbedtls subset, only the AES and DES block ciphers are used. CMAC and
# the DESFire CRCs are implemented in the library itself
set(NXPSC_MBEDTLS_SOURCES
    third_party/mbedtls/aes.c
    third_party/mbedtls/aesni.c
    third_party/mbedtls/des.c
    third_party/mbedtls/padlock.c
    third_party/mbedtls/platform_util.c
)

set(NXPSC_WARNINGS -Wall -Wextra)
if(MSVC)
    set(NXPSC_WARNINGS /W3)
endif()

add_library(nxpsc_obj OBJECT ${NXPSC_SOURCES} ${NXPSC_MBEDTLS_SOURCES})
target_include_directories(nxpsc_obj PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
target_compile_options(nxpsc_obj PRIVATE ${NXPSC_WARNINGS})
set_property(TARGET nxpsc_obj PROPERTY POSITION_INDEPENDENT_CODE ON)

add_library(nxpsc STATIC $<TARGET_OBJECTS:nxpsc_obj>)
target_include_directories(nxpsc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(NXPSC_BUILD_SHARED)
    add_library(nxpsc_shared SHARED $<TARGET_OBJECTS:nxpsc_obj>)
    set_target_properties(nxpsc_shared PROPERTIES
        OUTPUT_NAME nxpsc
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        # the headers carry no __declspec(dllexport), so without this an MSVC
        # build produces an nxpsc.dll that exports nothing. every non-static
        # symbol is exported, which is what the ELF and MinGW builds already do
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )
    # MSVC names both the static library and the DLL's import library
    # nxpsc.lib, and the build refuses to produce two files of the same name.
    # nxpsc.lib stays the static library, the import library becomes
    # nxpsc.dll.lib. MinGW already tells them apart (libnxpsc.a, libnxpsc.dll.a)
    if(MSVC)
        set_target_properties(nxpsc_shared PROPERTIES IMPORT_SUFFIX ".dll.lib")
    endif()
    target_include_directories(nxpsc_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
endif()

# the default RNG uses BCryptGenRandom on Windows
if(WIN32)
    target_link_libraries(nxpsc INTERFACE bcrypt)
    if(NXPSC_BUILD_SHARED)
        target_link_libraries(nxpsc_shared PRIVATE bcrypt)
    endif()
endif()

if(NXPSC_BUILD_TESTS)
    enable_testing()

    add_executable(nxpsc_test_crypto tests/test_crypto.c)
    target_link_libraries(nxpsc_test_crypto PRIVATE nxpsc)
    target_compile_options(nxpsc_test_crypto PRIVATE ${NXPSC_WARNINGS})
    if(WIN32)
        target_link_libraries(nxpsc_test_crypto PRIVATE bcrypt)
    endif()
    add_test(NAME crypto COMMAND nxpsc_test_crypto)

    add_executable(nxpsc_test_protocol tests/test_protocol.c tests/mockcard.c)
    target_link_libraries(nxpsc_test_protocol PRIVATE nxpsc)
    target_include_directories(nxpsc_test_protocol PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
    target_compile_options(nxpsc_test_protocol PRIVATE ${NXPSC_WARNINGS})
    if(WIN32)
        target_link_libraries(nxpsc_test_protocol PRIVATE bcrypt)
    endif()
    add_test(NAME protocol COMMAND nxpsc_test_protocol)
endif()

if(NXPSC_BUILD_EXAMPLES)
    add_executable(nxpsc_personalize examples/personalize.c examples/loopback.c)
    target_link_libraries(nxpsc_personalize PRIVATE nxpsc)
    target_include_directories(nxpsc_personalize PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/examples)
    target_compile_options(nxpsc_personalize PRIVATE ${NXPSC_WARNINGS})
    if(WIN32)
        target_link_libraries(nxpsc_personalize PRIVATE bcrypt)
    endif()

    # reclaim talks to a real reader, so it is only built where PC/SC is
    if(WIN32)
        set(NXPSC_PCSC_LIBS winscard)
    elseif(APPLE)
        find_library(NXPSC_PCSC_FRAMEWORK PCSC)
        set(NXPSC_PCSC_LIBS ${NXPSC_PCSC_FRAMEWORK})
    else()
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(PCSCLITE QUIET libpcsclite)
            if(PCSCLITE_FOUND)
                set(NXPSC_PCSC_LIBS ${PCSCLITE_LIBRARIES})
            endif()
        endif()
    endif()

    if(NXPSC_PCSC_LIBS)
        add_executable(nxpsc_reclaim examples/reclaim.c)
        target_link_libraries(nxpsc_reclaim PRIVATE nxpsc ${NXPSC_PCSC_LIBS})
        target_compile_options(nxpsc_reclaim PRIVATE ${NXPSC_WARNINGS})
        if(PCSCLITE_FOUND)
            target_include_directories(nxpsc_reclaim PRIVATE ${PCSCLITE_INCLUDE_DIRS})
            target_link_directories(nxpsc_reclaim PRIVATE ${PCSCLITE_LIBRARY_DIRS})
        endif()
        if(WIN32)
            target_link_libraries(nxpsc_reclaim PRIVATE bcrypt)
        endif()
    else()
        message(STATUS "PC/SC not found, skipping the nxpsc_reclaim example")
    endif()
endif()

include(GNUInstallDirs)
install(TARGETS nxpsc ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
if(NXPSC_BUILD_SHARED)
    # ARCHIVE is the Windows import library (nxpsc.dll.lib / libnxpsc.dll.a)
    install(TARGETS nxpsc_shared LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(DIRECTORY include/nxpsc DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(libnxpsc.pc.in libnxpsc.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libnxpsc.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
