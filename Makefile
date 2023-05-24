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
ifneq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_NANOS2))
$(error Environment variable TARGET_NAME is not valid or not supported)
endif

APPNAME = "Security Key"

APP_LOAD_PARAMS  = --curve secp256r1
APP_LOAD_PARAMS += --path "5722689'"  # int("WRA".encode("ascii").hex(), 16)
APP_LOAD_PARAMS += --path "5262163'"  # int("PKS".encode("ascii").hex(), 16)
APP_LOAD_PARAMS += --appFlags 0x040
APP_LOAD_PARAMS += $(COMMON_LOAD_PARAMS)

APPVERSION_M=1
APPVERSION_N=0
APPVERSION_P=1
APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

ICONNAME=icons/icon_security_key.gif

################
# Default rule #
################

all: default

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

############
# Platform #
############

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_SPRINTF
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

DEFINES += HAVE_U2F HAVE_IO_U2F
DEFINES += HAVE_FIDO2
DEFINES += USB_SEGMENT_SIZE=64
DEFINES += CUSTOM_IO_APDU_BUFFER_SIZE=1031 # 1024 + 7
DEFINES += UNUSED\(x\)=\(void\)x
DEFINES += APPVERSION=\"$(APPVERSION)\"

# Enforce SDK that supports UX Flow for Nano all targets, Nano S included
DEFINES += HAVE_UX_FLOW
DEFINES += HAVE_BAGL

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_NANOS2))
DEFINES += HAVE_GLO096
DEFINES += BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

# Enabling debug PRINTF
DEBUG=0
ifneq ($(DEBUG),0)
    ifeq ($(TARGET_NAME),TARGET_NANOX)
        DEFINES += HAVE_PRINTF PRINTF=mcu_usb_printf
    else
        DEFINES += HAVE_PRINTF PRINTF=screen_printf
    endif
else
        DEFINES += PRINTF\(...\)=
endif

DEFINES += HAVE_UX_STACK_INIT_KEEP_TICKER

###############
# Application #
###############

# Used to initialize app counter to current timestamp directly in the app bin code
# when the app is streamed from the HSM.
# This is necessary to never use the counter with a lower value than previous calls.
# This means that the app APDU will be patched when streamed from the HSM and therefore
# the apdu should not contain a crc.
DEFINES += HAVE_COUNTER_MARKER
APP_LOAD_PARAMS += --nocrc

# Disable resetGeneration increment during ctap2 reset
# This means credentials that are not discoverable won't be properly
# revocated anymore. Now not that due to the fact this resetGeneration
# counter was in NVM, it was reset to 0 after each app reinstallation (due
# to an app update, a firmware update, or just a user triggered uninstall
# then reinstall flow), and this reset was causing even more issues
DEFINES += HAVE_NO_RESET_GENERATION_INCREMENT

# Disable by default rk support and expose a setting to enable it
# This means that by default user won't be able to create "Resident Keys",
# which are also named "Discoverable Credentials".
# This has been implemented to protect user from the nvram wipe mostly happening
# during an app update which will erase their RK credentials we no possibility
# to restore them.
# Advanced user can still choose to enable this setting at their own risk.
DEFINES += HAVE_RK_SUPPORT_SETTING

DEFINES += HAVE_FIDO2_RPID_FILTER

DEFINES += RK_SIZE=6144

#DEFINES  += HAVE_CBOR_DEBUG

##############
# Compiler #
##############

WERROR=0
ifneq ($(WERROR),0)
    CFLAGS += -Werror
endif

CC      := $(CLANGPATH)clang
CFLAGS  += -O3 -Os
AS      := $(GCCPATH)arm-none-eabi-gcc
LD      := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS  += -lm -lgcc -lc

# Remove warning on custom snprintf implementation usage
CFLAGS += -Wno-format-invalid-specifier -Wno-format-extra-args

# Import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

# Define directory to build
APP_SOURCE_PATH  += src src-cbor
SDK_SOURCE_PATH  += lib_stusb lib_ux lib_u2f lib_stusb_impl

load: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python3 -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# Import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

# Add dependency on custom makefile filename
dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS NONE SecurityKey
