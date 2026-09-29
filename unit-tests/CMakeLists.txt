cmake_minimum_required(VERSION 3.28)
project(UNIT_TESTS
    VERSION 0.1
    DESCRIPTION "Unit tests for the Security Key application"
    LANGUAGES C
)

#######################################################################
#                        Setup SDK & LedgerUT                         #
#######################################################################
if(NOT DEFINED ENV{BOLOS_SDK})
    message(FATAL_ERROR "BOLOS_SDK environment variable is not set. Please set it to the path of the Ledger Secure SDK.")
endif()

set(SDK_DIR $ENV{BOLOS_SDK})
list(APPEND CMAKE_MODULE_PATH "${SDK_DIR}/cmake")
include(LedgerUT)

#######################################################################
#             Setup app specific includes & compile defs              #
#######################################################################
set(APP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

set(UT_INCLUDE_DIRS
    ${CMAKE_BINARY_DIR}/mocks/
    ${APP_DIR}/include
    ${APP_DIR}/src
    ${APP_DIR}/src/ctap2
    ${APP_DIR}/src/ctap2/get_assertion
    ${APP_DIR}/src/ctap2/make_credential
    ${APP_DIR}/src/ctap2/reset
    ${APP_DIR}/cbor-src
    ${CMAKE_CURRENT_SOURCE_DIR}/fakes
)

# Mirrors the DEFINES of the app Makefile that shape the code under test.
set(UT_COMPILE_DEFS
    APPNAME="Security Key"
    APPVERSION="9.9.9"
    HAVE_U2F
    HAVE_FIDO2
    HAVE_NFC
    CUSTOM_IO_APDU_BUFFER_SIZE=1031
    HAVE_COUNTER_MARKER
    COUNTER_MARKER=0xF1D0C001
    HAVE_NO_RESET_GENERATION_INCREMENT
    ENABLE_RK_CONFIG
    HAVE_FIDO2_RPID_FILTER
    RK_SIZE=6144
)

# The CBOR code is plain C: it builds without the SDK, under the sanitizers.
set(UT_CBOR_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${APP_DIR}/cbor-src
)
set(UT_CBOR_COMPILE_DEFS
    UNIT_TESTS
    CBOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/cbor"
)
set(UT_SANITIZERS -fsanitize=address,undefined -fno-sanitize-recover=undefined)

#######################################################################
#                           LedgerUT Setup                            #
#######################################################################
ledger_unit_tests_init()

# build all app sources but app_main.c (coverage baseline; not linked by tests)
ledger_unit_tests_find_sources()

ledger_unit_tests_build_app_sources_as_lib(
    SOURCES      ${APP_SOURCES}
    INCLUDE_DIRS ${UT_INCLUDE_DIRS}
    COMPILE_DEFS ${UT_COMPILE_DEFS}
)

#######################################################################
#                        LedgerUT test suites                         #
#######################################################################
ledger_unit_tests_add_test(
    NAME            test_cbip_encode
    SOURCES         ${APP_DIR}/cbor-src/cbip_encode.c
    INCLUDE_DIRS    ${UT_CBOR_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_CBOR_COMPILE_DEFS}
    COMPILE_OPTIONS ${UT_SANITIZERS}
    LINK_OPTIONS    ${UT_SANITIZERS}
)

ledger_unit_tests_add_test(
    NAME            test_cbip_decode
    SOURCES         ${APP_DIR}/cbor-src/cbip_decode.c
    INCLUDE_DIRS    ${UT_CBOR_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_CBOR_COMPILE_DEFS}
    COMPILE_OPTIONS ${UT_SANITIZERS}
    LINK_OPTIONS    ${UT_SANITIZERS}
)

ledger_unit_tests_add_test(
    NAME            test_config
    SOURCES         ${APP_DIR}/src/config.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/stubs/stub_config.c
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/stubs
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)
