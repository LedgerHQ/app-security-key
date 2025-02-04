# Ledger App Security Key

Ledger App Security Key for Ledger devices.

This application implements an U2F and CTAP2 Authenticator for Ledger devices.

A great introduction to WebAuthn can be found [here](https://webauthn.me/introduction).
You can also use [this demo](https://webauthn.me/) to test this app, or use [its debugger](https://webauthn.me/debugger) to do some advance testing.


## Specifications

* FIDO U2F 1.2
  - [Universal 2nd Factor (U2F) Overview, 11 April 2017](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html)
  - [FIDO U2F Raw Message Formats, 11 April 2017](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html) :white_check_mark:

* FIDO2
  - CTAP
    - [Client to Authenticator Protocol (CTAP 2.0), Proposed Standard, January 30, 2019](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html) :white_check_mark:
    - [Client to Authenticator Protocol (CTAP 2.1), Proposed Standard, June 21, 2022](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html) :new:
    - [Client to Authenticator Protocol (CTAP 2.2), Review Draft, October 03, 2024](https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html) :construction_worker:
  - WebAuthn
    - [Web Authentication: An API for accessing Public Key Credentials Level 2, W3C Recommendation, 8 April 2021](https://www.w3.org/TR/2021/REC-webauthn-2-20210408) :new:
    - [Web Authentication: An API for accessing Public Key Credentials Level 3, W3C Working Draft, 27 January 2025](https://www.w3.org/TR/2025/WD-webauthn-3-20250127/) :construction_worker:

## Building

### With VSCode

You can quickly setup a convenient environment to build and test your application by using [Ledger's VSCode developer tools extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools) which leverages the [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools) docker image.

### With a terminal

The [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools) docker image contains all the required tools and libraries to **build**, **test** and **load** an application.

## Acronyms

Acronyms specific to the project:

* CBIP: CBOR in place

Acronyms not specific to the project:

* CBOR: Concise Binary Object Representation (serialization format standardized as [RFC7049](https://tools.ietf.org/html/rfc7049) and described on [Wikipedia](https://en.wikipedia.org/wiki/CBOR))
* COSE: CBOR Object Signing and Encryption (serialization format standardized as [RFC8152](https://tools.ietf.org/html/rfc8152) which uses [identifiers assigned by IANA](https://www.iana.org/assignments/cose/cose.xhtml))
* CTAP: Client to Authenticator Protocol (component of FIDO2 specifications, described on [FIDO Alliance's website](https://fidoalliance.org/specifications/download/))
* FIDO2: Fast IDentity Online (open authentication standard, hosted by the [FIDO Alliance](https://fidoalliance.org/fido2/))
* U2F: Universal 2nd Factor (open authentication standard, precedes FIDO2)
* WebAuthn: Web Authentication (component of FIDO2 specifications, described on [FIDO Alliance's website](https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/))
* UP: User Presence (for example clicking buttons)
* UV: User Verification (for example verifying a PIN code)


## Testing the app

See dedicated `README.md` in tests `directory`.


## Known limitations

- On Firefox on Linux, Nano S Plus is missing in snap udev rules.
- There are some instabilities on Safari on MacOS, it's recommended to use another browser.
- On Android, it is supported as soon as you have Google Play services v23.35 or above and that the service configuration doesn't require Discoverable Credentials.

Due to OS constraints, this Security Key App has some limitations:

* Discoverable / Resident credentials are supported but are stored on a part of the device flash that will be wiped upon app deletion, which can happen:
  - If the user chooses to uninstall it from Ledger Live
  - If the user chooses to update the app to a new available version
  - If the user updates the OS version
  That is why they are not enabled by default, and should be manually enabled in the settings. See HAVE_RK_SUPPORT_SETTING section on the Makefile for more explanations.
* Following FIDO2 spec, there should be a way to revoked credentials. A revocation mechanism has been implemented based on a counter that - as discoverable credentials - will be wiped upon app deletion. therefore, in order to avoid weird issue on user side, this counter as been disabled. See HAVE_NO_RESET_GENERATION_INCREMENT section on the Makefile for more explanations.

Please look at the dedicated section at the end of [this blog post](https://www.ledger.com/blog/strengthen-the-security-of-your-accounts-with-webauthn) for more detailed explanations.
