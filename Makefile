#******************************************************************************
#   Ledger App Security Key
#   (c) 2022 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#   limitations under the License.
#*******************************************************************************/

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

$(info TARGET_NAME=$(TARGET_NAME))
ifneq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOS TARGET_NANOX TARGET_NANOS2 TARGET_STAX TARGET_FLEX TARGET_APEX_P))
$(error Environment variable TARGET_NAME is not valid or not supported)
endif

APPNAME = "Security Key"

CURVE_APP_LOAD_PARAMS = secp256r1
PATH_APP_LOAD_PARAMS = "5722689'"  # int("WRA".encode("ascii").hex(), 16)
PATH_APP_LOAD_PARAMS += "5262163'"  # int("PKS".encode("ascii").hex(), 16)

APPVERSION_M=1
APPVERSION_N=7
APPVERSION_P=1
APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

ICON_NANOS=icons/icon_security_key_nanos.gif
ICON_NANOX=icons/icon_security_key.gif
ICON_NANOSP=icons/icon_security_key.gif
ICON_STAX=icons/icon_security_key_stax.gif
ICON_FLEX=icons/icon_security_key_flex.gif
ICON_APEX_P=icons/icon_security_key_apex_p.gif

################
# Attestations #
################
PROD_U2F_NANOS_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_NANOS_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_NANOS_PRIVATE_KEY=${PROD_U2F_NANOS_PRIVATE_KEY}
endif

PROD_FIDO2_NANOS_PRIVATE_KEY?=0
ifneq ($(PROD_FIDO2_NANOS_PRIVATE_KEY),0)
    DEFINES += PROD_FIDO2_NANOS_PRIVATE_KEY=${PROD_FIDO2_NANOS_PRIVATE_KEY}
endif

PROD_U2F_NANOX_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_NANOX_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_NANOX_PRIVATE_KEY=${PROD_U2F_NANOX_PRIVATE_KEY}
endif

PROD_FIDO2_NANOX_PRIVATE_KEY?=0
ifneq ($(PROD_FIDO2_NANOX_PRIVATE_KEY),0)
    DEFINES += PROD_FIDO2_NANOX_PRIVATE_KEY=${PROD_FIDO2_NANOX_PRIVATE_KEY}
endif

PROD_U2F_NANOSP_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_NANOSP_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_NANOSP_PRIVATE_KEY=${PROD_U2F_NANOSP_PRIVATE_KEY}
endif

PROD_FIDO2_NANOSP_PRIVATE_KEY?=0
ifneq ($(PROD_FIDO2_NANOSP_PRIVATE_KEY),0)
    DEFINES += PROD_FIDO2_NANOSP_PRIVATE_KEY=${PROD_FIDO2_NANOSP_PRIVATE_KEY}
endif

PROD_U2F_STAX_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_STAX_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_STAX_PRIVATE_KEY=${PROD_U2F_STAX_PRIVATE_KEY}
endif

PROD_FIDO2_STAX_PRIVATE_KEY?=0
ifneq ($(PROD_FIDO2_STAX_PRIVATE_KEY),0)
    DEFINES += PROD_FIDO2_STAX_PRIVATE_KEY=${PROD_FIDO2_STAX_PRIVATE_KEY}
endif

PROD_U2F_FLEX_PRIVATE_KEY?=0
ifneq ($(PROD_U2F_FLEX_PRIVATE_KEY),0)
    DEFINES += PROD_U2F_FLEX_PRIVATE_KEY=${PROD_U2F_FLEX_PRIVATE_KEY}
endif

PROD_FIDO2_FLEX_PRIVATE_KEY?=0
ifneq ($(PROD_FIDO2_FLEX_PRIVATE_KEY),0)
    DEFINES += PROD_FIDO2_FLEX_PRIVATE_KEY=${PROD_FIDO2_FLEX_PRIVATE_KEY}
endif

############
# Platform #
############

DEFINES += HAVE_U2F HAVE_IO_U2F
DEFINES += HAVE_FIDO2
DEFINES += CUSTOM_IO_APDU_BUFFER_SIZE=1031 # 1024 + 7

DEFINES += HAVE_BOLOS_APP_STACK_CANARY

###############
# Application #
###############

# Used to initialize app counter to current timestamp directly in the app bin code
# when the app is streamed from the HSM.
# This is necessary to never use the counter with a lower value than previous calls.
# This means that the app APDU will be patched when streamed from the HSM and therefore
# the apdu should not contain a crc.
DEFINES += HAVE_COUNTER_MARKER
ENABLE_NOCRC_APP_LOAD_PARAMS = 1
# required for the marker to be found in the app binary
CFLAGS += -mno-movt

# Disable resetGeneration increment during ctap2 reset
# This means credentials that are not discoverable won't be properly
# revocated anymore. Now not that due to the fact this resetGeneration
# counter was in NVM, it was reset to 0 after each app reinstallation (due
# to an app update, a firmware update, or just a user triggered uninstall
# then reinstall flow), and this reset was causing even more issues
DEFINES += HAVE_NO_RESET_GENERATION_INCREMENT

# These 2 flags allow to enable/disable the RK feature and expose an app setting for it.
# This has been implemented to protect user from the NVRAM wipe mostly happening during
# an app update which will erase their RK credentials with no possibility  to restore them.
#
# ENABLE_RK_CONFIG activates the internal code which allows to activate and deactivate
# the feature. It sets the feature as deactivated by default.
# ENABLE_RK_CONFIG_UI_SETTING activates the UI settings which allows a user to enable or
# disable the feature.
#
# So the expected behaviors are the following:
# - No flags -> RK are enabled by default and a user can not deactivate the feature,
# - ENABLE_RK_CONFIG only -> RK are disabled by default and a user can not activate the feature,
# - ENABLE_RK_CONFIG_UI_SETTING only -> compilation fails at link,
# - ENABLE_RK_CONFIG & ENABLE_RK_CONFIG_UI_SETTING -> RK are disabled by default but a user can
#   enable or disable the feature through the app's settings.
DEFINES += ENABLE_RK_CONFIG
ifeq ($(ENABLE_RK_CONFIG_UI_SETTING),1)
DEFINES += ENABLE_RK_CONFIG_UI_SETTING
endif

DEFINES += HAVE_FIDO2_RPID_FILTER

ifeq ($(TARGET_NAME),TARGET_NANOS)
DEFINES += RK_SIZE=2048
else
DEFINES += RK_SIZE=6144
endif

DISABLE_OS_IO_STACK_USE = 1

ifneq ($(DEBUG), 0)
    DEFINES += DEBUG_UI
endif
#DEFINES  += HAVE_CBOR_DEBUG

# The flag that fakes the NFC transport for U2F
ifeq ($(ENABLE_U2F_OVER_FAKE_NFC_TESTS),1)
DEFINES += HAVE_U2F_OVER_FAKE_NFC_TESTS
endif

ENABLE_NFC = 1

##############
# Compiler #
##############

# Application source files
APP_SOURCE_PATH  += src cbor-src
SDK_SOURCE_PATH  += lib_u2f

ifeq ($(API_LEVEL),)
# Specific files for Nanos device which OS CX lib doesn't provide the needed
# AES_SIV functions.
# Check on API_LEVEL rather than TARGET_NAME to allow compilation on unified SDK.
DEFINES += HAVE_AES_SIV HAVE_AES HAVE_CMAC
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src
APP_SOURCE_FILES += $(BOLOS_SDK)/lib_cxng/src/cx_ram.c
APP_SOURCE_PATH  += sdk-lib-cxng-copy
endif

VARIANT_PARAM = APP
VARIANT_VALUES = SecurityKey

include $(BOLOS_SDK)/Makefile.standard_app
