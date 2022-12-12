# FIDO Conformance

## Conformance Tools

Conformance Tools can be used to test an authentication or server implementation.
Conformance Tools can be downloaded from FIDO Alliance server with a dedicated login.

## General advice

Be fast, the tests have low timeouts. Especially when you need to enter device PIN.
Some debugging info can be retrieved by using `MENU`->`Open inspector`->`Console`. However, be aware that not every exchange are logged, at least replay are not shown. 

## Metadata files

This directory contains metadata files for both `test` and `prod` environment each device.
The only difference between `test` and `prod` file must be the `attestationRootCertificates` value which should be the `ca-cert` of each environment.

## Last Conformance run

Running with Windows FIDO Conformance Tools v1.7.5

### U2F1.1/1.2

Detected failures:
- Test transports:
	+ HID-1 Test U2F HID support
		* F-4: "Send a valid CTAPHID_PING, with a a large payload size(1024 bytes), that has a continuation frame with a SEQ that is out of order"
		  => timeout instead of returning CTAPHID_ERROR with error ERR_INVALID_SEQ
- Test Registration and Test Authentication:
	+ General failure linked to https://github.com/fido-alliance/conformance-test-tools-resources/issues/574
- Metadata tests:
	+ Many failures due to the fact metadata files contains info for CTAP2 tests which are not the one required by U2F tests


### CTAP2.0 Authenticator - MDS3 Tests

Detected failures:
- Options: Resident Key:
	+ P-4: "Expected authenticator to succeed with CTAP1_ERR_SUCCESS(0). Got CTAP2_ERR_PUAT_REQUIRED(54)"
	=> This seems to be due to a Conformance Tools issue as when looking at inspector  console log the tools set a client Pin before sending make_credentials request without pinAuth parameter, which as per the FIDO2.0 specification (5.1.7) should be answered with CTAP2_ERR_PIN_REQUIRED(0x36 / 54).
- Ext: HMAC Secret:
	+ P-4: "Authenticator returned the same HMAC for both UV and non-UV credential!"
	=> Having two different CredRandom for UV and non-UV credential is required in FIDO2.1 specification. However, in FIDO2.0 specification, a single CredRandom is specified.
