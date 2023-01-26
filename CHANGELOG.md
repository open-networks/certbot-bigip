# certbot-bigip plugin change log

## 1.2.0 - 2023-01-26

### Added

- Added renew_deploy functionality to trigger an install after a successfull renew
- Added support for elliptic curve certificates

### Changed

- Updated Readme to new parameter syntax and renew behaviour

### Removed

-

### Fixed

- Fixed iRule to disable HTTP event after execution
- Fixed Standalone handling

## 1.1.0 - 2021-05-01

### Added

- Plugin supports now Standalone BIG-IPs
- Plugin now deploys to the active BIG-IP
- Added verify-ssl parameter to enable or disable verification of the BIG-IP management API certificate, defaults to False to not have breakting changes. Might change in the future.

### Changed

-

### Removed

-

### Fixed

- Updated code for public release
- Updated documentation

## 1.0.4 - 2021-02-18

### Added

-

### Changed

-

### Removed

-

### Fixed

- Fixed setup.py

## 1.0.3 - 2021-02-18

### Added

-

### Changed

-

### Removed

-

### Fixed

- Fixed situation with an empty parameter

## 1.0.2 - 2020-02-10

### Added

- Initial release - double tag

### Changed

-

### Removed

-

### Fixed

-

## 1.0.1 - 2020-02-10

### Added

- Initial release

### Changed

-

### Removed

-

### Fixed

-
