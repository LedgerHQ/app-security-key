# Ledger App Security Key

Ledger App Security Key for Ledger devices.

This application implements an U2F and CTAP2 Authenticator for Ledger devices.

A great introduction to WebAuthn can be found [here](https://webauthn.me/introduction).
You can also use [this demo](https://webauthn.me/) to test this app, or use [its debugger](https://webauthn.me/debugger) to do some advance testing.


## Specifications

* FIDO U2F (CTAP 1) specification can be found [here](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html).
* FIDO v2 (CTAP 2) specification can be found [here](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html).
* FIDO v2.1 (CTAP 2.1) specification can be found [here](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html).


## Building

On a development environment:

* Set `BOLOS_SDK` to a place where the Nano S SDK has been cloned (<https://github.com/LedgerHQ/nanos-secure-sdk>)
* Until the SDK patch have not been integrated, you need to patch the SDK with the needed fix available in `sdk-patch` directory.
* Install `arm-none-eabi-gcc` and `clang`
* Run `make`


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

On Linux and Mac, Firefox support only U2F but not CTAP2, see [corresponding tracker](https://bugzilla.mozilla.org/show_bug.cgi?id=1530370).
