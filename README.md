# Ledger App Security Key

Ledger App Security Key for Ledger devices.

This application implements a U2F and CTAP2 Authenticator for Ledger devices.

A great introduction to WebAuthn can be found [here](https://webauthn.me/introduction).
You can also use [this demo](https://webauthn.io/) to test this app, or use [this debugger](https://webauthn.me/debugger) to do some advanced testing.


## Specifications

* FIDO U2F 1.2
  - [Universal 2nd Factor (U2F) Overview, 11 April 2017](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html) :white_check_mark:
  - [FIDO U2F Raw Message Formats, 11 April 2017](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html) :white_check_mark:

* FIDO2
  - CTAP
    - [Client to Authenticator Protocol (CTAP 2.0), Proposed Standard, January 30, 2019](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html) :white_check_mark:
    - [Client to Authenticator Protocol (CTAP 2.1), Proposed Standard, June 21, 2022](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html)
    - [Client to Authenticator Protocol (CTAP 2.2), Proposed Standard, July 14, 2025](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
    - [Client to Authenticator Protocol (CTAP 2.3), Proposed Standard, February 26, 2026](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
  - WebAuthn
    - [Web Authentication: An API for accessing Public Key Credentials Level 2, W3C Recommendation, 8 April 2021](https://www.w3.org/TR/2021/REC-webauthn-2-20210408)
    - [Web Authentication: An API for accessing Public Key Credentials Level 3, W3C Candidate Recommendation, 26 May 2026](https://www.w3.org/TR/webauthn-3/)

## Building

### With VSCode

You can quickly setup a convenient environment to build and test your application by using [Ledger's VSCode developer tools extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools) which leverages the [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools) docker image.

### With a terminal

The [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools) docker image contains all the required tools and libraries to **build**, **test** and **load** an application.

## Acronyms

Acronyms specific to the project:

* CBIP: CBOR in place

Acronyms not specific to the project:

* CBOR: Concise Binary Object Representation (serialization format standardized as [RFC8949](https://tools.ietf.org/html/rfc8949) and described on [Wikipedia](https://en.wikipedia.org/wiki/CBOR))
* COSE: CBOR Object Signing and Encryption (serialization format standardized as [RFC9052](https://tools.ietf.org/html/rfc9052) which uses [identifiers assigned by IANA](https://www.iana.org/assignments/cose/cose.xhtml))
* CTAP: Client to Authenticator Protocol (component of FIDO2 specifications, described on [FIDO Alliance's website](https://fidoalliance.org/specifications/download/))
* FIDO2: Fast IDentity Online (open authentication standard, hosted by the [FIDO Alliance](https://fidoalliance.org/fido2/))
* U2F: Universal 2nd Factor (open authentication standard, precedes FIDO2)
* WebAuthn: Web Authentication (component of FIDO2 specifications, described on [FIDO Alliance's website](https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/))
* UP: User Presence (for example clicking buttons)
* UV: User Verification (for example verifying a PIN code)


## Testing the app

See dedicated `README.md` in the `tests/` directory.


## Known limitations

* Discoverable / Resident credentials are currently disabled. The underlying constraint is that they are stored on a part of the device flash that gets wiped upon app deletion (on uninstall, app update, or OS update). Properly supporting this feature therefore requires a full backup and restore infrastructure spanning multiple components of the stack. Work is ongoing. See `ENABLE_RK_CONFIG` and `ENABLE_RK_CONFIG_UI_SETTING` in the `Makefile` for implementation details.
* Following FIDO2 spec, there should be a way to revoke credentials. A revocation mechanism has been implemented based on a counter that - just like discoverable credentials - will be wiped upon app deletion. Therefore, in order to avoid unexpected issues on the user side, this counter has been disabled. See `HAVE_NO_RESET_GENERATION_INCREMENT` in the `Makefile` for more details.

For more details, see the [blog post](https://www.ledger.com/blog/strengthen-the-security-of-your-accounts-with-webauthn) and the [Ledger support article](https://support.ledger.com/article/12350325732893-zd).

## Other Use Cases

Beyond website and app authentication, the Security Key app can be used as a hardware factor in several workflows:

- **Git SSH authentication** — hardware-bound SSH key for GitHub, GitLab, and remote servers. See [doc/usecase-git-auth.md](doc/usecase-git-auth.md).
- **Git commit signing** — SSH-based commit and tag signatures, requiring a physical tap per commit. See [doc/usecase-git-signing.md](doc/usecase-git-signing.md).
- **LUKS2 volume encryption** — unlock an encrypted image file or partition by tapping the device, using the `hmac-secret` FIDO2 extension. See [doc/usecase-luks.md](doc/usecase-luks.md).
