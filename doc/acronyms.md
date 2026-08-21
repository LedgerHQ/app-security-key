# Acronyms

## Project-specific

* CBIP: CBOR in place
* RK: Resident Key (synonym for Discoverable Credential; a credential stored on the authenticator and retrievable by the RP without a prior credential ID)

## General

* AAGUID: Authenticator Attestation Globally Unique Identifier (a 128-bit identifier that identifies the authenticator model, included in the attestation statement)
* APDU: Application Protocol Data Unit (command/response frame format used over USB HID and NFC transports)
* CBOR: Concise Binary Object Representation (serialization format standardized as [RFC8949](https://tools.ietf.org/html/rfc8949) and described on [Wikipedia](https://en.wikipedia.org/wiki/CBOR))
* COSE: CBOR Object Signing and Encryption (serialization format standardized as [RFC9052](https://tools.ietf.org/html/rfc9052) which uses [identifiers assigned by IANA](https://www.iana.org/assignments/cose/cose.xhtml))
* CTAP: Client to Authenticator Protocol (component of FIDO2 specifications, described on [FIDO Alliance's website](https://fidoalliance.org/specifications/download/))
* FIDO2: Fast IDentity Online (open authentication standard, hosted by the [FIDO Alliance](https://fidoalliance.org/fido2/))
* HID: Human Interface Device (USB device class used as the primary transport for CTAP over USB)
* HMAC: Hash-based Message Authentication Code (used notably in the `hmac-secret` CTAP extension, which enables LUKS2 volume unlock)
* NFC: Near Field Communication (contactless transport supported alongside USB HID)
* RP: Relying Party (the website or service that requests authentication from the authenticator)
* U2F: Universal 2nd Factor (open authentication standard, precedes FIDO2)
* UP: User Presence (low-friction confirmation, for example tapping the device screen)
* UV: User Verification (stronger confirmation, for example verifying a PIN code)
* WebAuthn: Web Authentication (component of FIDO2 specifications, described on [FIDO Alliance's website](https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/))
