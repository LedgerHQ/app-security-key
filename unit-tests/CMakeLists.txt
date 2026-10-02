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

ledger_unit_tests_add_test(
    NAME            test_client_pin
    SOURCES         ${APP_DIR}/src/cbip_helper.c
                    ${APP_DIR}/cbor-src/cbip_decode.c
                    ${APP_DIR}/cbor-src/cbip_encode.c
    MOCK_HEADERS    ${SDK_DIR}/lib_cxng/include/lcx_aes.h
                    ${SDK_DIR}/lib_cxng/include/lcx_ecdh.h
                    ${SDK_DIR}/lib_cxng/include/lcx_ecfp.h
                    ${SDK_DIR}/lib_cxng/include/lcx_hmac.h
                    ${SDK_DIR}/lib_cxng/include/lcx_rng.h
                    ${SDK_DIR}/lib_cxng/include/lcx_sha256.h
                    ${APP_DIR}/include/config.h
                    ${APP_DIR}/include/crypto.h
                    ${APP_DIR}/include/cose_keys.h
                    ${APP_DIR}/src/ctap2/ctap2_utils.h
                    ${SDK_DIR}/include/ledger_assert_internals.h
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
    # The generated mocks include crypto.h and cose_keys.h alone, and those expect os.h/cx.h first.
    COMPILE_OPTIONS "SHELL:-include os.h" "SHELL:-include cx.h"
)

ledger_unit_tests_add_test(
    NAME            test_crypto
    MOCK_HEADERS    ${SDK_DIR}/lib_cxng/include/lcx_ecfp.h
                    ${SDK_DIR}/lib_cxng/include/lcx_hash.h
                    ${SDK_DIR}/lib_cxng/include/lcx_sha256.h
                    ${SDK_DIR}/include/ledger_assert_internals.h
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME            test_credential
    SOURCES         ${APP_DIR}/src/cbip_helper.c
                    ${APP_DIR}/cbor-src/cbip_decode.c
                    ${APP_DIR}/cbor-src/cbip_encode.c
    MOCK_HEADERS    ${SDK_DIR}/lib_cxng/include/lcx_aes_siv.h
                    ${APP_DIR}/include/config.h
                    ${APP_DIR}/include/cose_keys.h
                    ${APP_DIR}/include/crypto.h
                    ${APP_DIR}/src/ctap2/rk_storage.h
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
    COMPILE_OPTIONS "SHELL:-include os.h" "SHELL:-include cx.h"
)

ledger_unit_tests_add_test(
    NAME            test_processing
    SOURCES         ${APP_DIR}/src/globals.c
                    ${APP_DIR}/src/string_utils.c
                    ${APP_DIR}/src/cbip_helper.c
                    ${APP_DIR}/cbor-src/cbip_decode.c
                    ${APP_DIR}/cbor-src/cbip_encode.c
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME            test_get_next_assertion
    SOURCES         ${APP_DIR}/src/globals.c
                    ${APP_DIR}/src/string_utils.c
    MOCK_HEADERS    ${APP_DIR}/src/ctap2/rk_storage.h
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME            test_u2f_processing_flow
    SOURCES         ${APP_DIR}/src/globals.c
                    ${APP_DIR}/src/string_utils.c
    MOCK_HEADERS    ${SDK_DIR}/lib_cxng/include/lcx_rng.h
                    ${SDK_DIR}/lib_cxng/include/lcx_sha256.h
                    ${APP_DIR}/include/config.h
                    ${APP_DIR}/include/credential.h
                    ${APP_DIR}/include/crypto.h
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
    COMPILE_OPTIONS "SHELL:-include os.h" "SHELL:-include cx.h"
)

ledger_unit_tests_add_test(
    NAME            test_get_assertion_utils
    SOURCES         ${APP_DIR}/src/globals.c
                    ${APP_DIR}/src/string_utils.c
                    ${APP_DIR}/src/cbip_helper.c
                    ${APP_DIR}/cbor-src/cbip_decode.c
                    ${APP_DIR}/cbor-src/cbip_encode.c
    MOCK_HEADERS    ${SDK_DIR}/lib_cxng/include/lcx_ecfp.h
                    ${SDK_DIR}/lib_cxng/include/lcx_hmac.h
                    ${SDK_DIR}/lib_cxng/include/lcx_rng.h
                    ${SDK_DIR}/lib_cxng/include/lcx_sha256.h
                    ${APP_DIR}/include/config.h
                    ${APP_DIR}/include/cose_keys.h
                    ${APP_DIR}/include/credential.h
                    ${APP_DIR}/include/crypto.h
                    ${APP_DIR}/include/ctap2.h
                    ${APP_DIR}/src/ctap2/ctap2_utils.h
                    ${APP_DIR}/src/ctap2/rk_storage.h
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
    COMPILE_OPTIONS "SHELL:-include os.h" "SHELL:-include cx.h"
)

ledger_unit_tests_add_test(
    NAME            test_make_credential_utils
    SOURCES         ${APP_DIR}/src/globals.c
                    ${APP_DIR}/src/string_utils.c
                    ${APP_DIR}/src/cbip_helper.c
                    ${APP_DIR}/cbor-src/cbip_decode.c
                    ${APP_DIR}/cbor-src/cbip_encode.c
    MOCK_HEADERS    ${SDK_DIR}/lib_cxng/include/lcx_ecfp.h
                    ${SDK_DIR}/lib_cxng/include/lcx_rng.h
                    ${SDK_DIR}/lib_cxng/include/lcx_sha256.h
                    ${APP_DIR}/include/config.h
                    ${APP_DIR}/include/cose_keys.h
                    ${APP_DIR}/include/credential.h
                    ${APP_DIR}/include/crypto.h
                    ${APP_DIR}/src/ctap2/ctap2_utils.h
                    ${APP_DIR}/src/ctap2/rk_storage.h
    INCLUDE_DIRS    ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS    ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
    COMPILE_OPTIONS "SHELL:-include os.h" "SHELL:-include cx.h"
)
