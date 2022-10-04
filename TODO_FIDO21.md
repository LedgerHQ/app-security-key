# FIDO21 implementation TODO

[x] Add AuthSelection

[ ] Add new PinAuth:
	[x] Implementation
	[ ] Tests (missing test on timers)
	[ ] Should we keep PIN/UV Auth Protocol One?
	[ ] 6.5.8. PRF values used => check if we are good?

[ ] Add credProtect

[x] Update makeCredential authenticator algorithm
	[x] new algorithm steps
	[x] new PinAuth management
	[ ] add credProtect handling
	[ ] discuss about deviations for user consent

[x] Update getAssertion authenticator algorithm
	[x] new algorithm steps
	[x] new PinAuth management
	[ ] add credProtect handling
	[ ] discuss about deviations for user consent

[ ] Add credManagment
	[ ] Include truncated rpId in rk storage?

[ ] HMAC Secret Extension: mandatory
	[ ] generate CredRandomWithoutUV
	[x] handle pinprotocolV2

[ ] Add credBlob?

[ ] Add largeBlob?

[ ] Add TxAuthGeneric?

[ ] Update Solokeys FIDO2 tests patchs

[ ] GetInfo
	[ ] change versions to FIDO_2_1, or just add?
	[ ] add new fields in getInfo response:
		[ ] remainingDiscoverableCredentials
		[ ] maxCredentialCountInList
		[ ] maxCredentialIdLength
		[ ] transports
		[ ] algorithms
		[ ] uvModality (https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#user-verification-methods)
		[ ] certifications
		[ ] forcePINChange (implies authenticatorConfig subcommand setMinPINLength is implemented)
	[ ] select options:
		[x] pinUvAuthToken => True "MUST include the pinUvAuthToken option ID with the value true in the authenticatorGetInfo response’s options member if either the clientPin or uv option IDs have the value true."
		[ ] noMcGaPermissionsWithClientPin => probably not for retrocompat?
		[ ] largeBlobs => see largeBlobs
		[ ] credMgmt => Probably supported
		[x] makeCredUvNotRqd => Probably True ("Authenticators SHOULD include this option with the value true.")
