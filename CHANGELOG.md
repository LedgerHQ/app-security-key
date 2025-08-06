# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.2] - 2024-08-06

### Fixed
- Catching up updated `API_LEVEL_24` SDK version with HID U2F fix

## [1.7.1] - 2024-07-24

### Fixed
- Using standard `app_exit()` function to handle properly USB stop/start (io revamp preparation)


## [1.7.0] - 2024-06-09

### Added

- Resident Keys: `GET_NEXT_ASSERTION` function implemented on Stax and Flex, available only over NFC
- On Stax and Flex, over NFC, `MAKE_CREDENTIAL` and `GET_ASSERTION` functions displays RP and user
  information of the current operation.

### Fixed

- UI: Status pages text and titles are now centered
- UI: displaying previously registered or asserted RP/user names in U2F-over-NFC mode


## [1.6.5] - 2024-10-09


### Fixed

- several UI aspects

## [1.6.4] - 2024-07-22

### Fixed

- Resident Keys: enabling option was removed, but RKs were activated by default


## [1.6.3] - 2024-07-18

### Fixed

- Resident Keys: disabled for production version


## [1.6.2] - 2024-07-11

### Fixed

- Internal minor fixes and changes

## [1.6.1] - 2024-06-26

### Fixed

- Minor UI improvements


## [1.6.0] - 2024-06-11

- Initial version for CHANGELOG
