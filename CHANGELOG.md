# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

### Categories each change fall into

* **Added**: for new features.
* **Changed**: for changes in existing functionality.
* **Deprecated**: for soon-to-be removed features.
* **Removed**: for now removed features.
* **Fixed**: for any bug fixes.
* **Security**: in case of vulnerabilities.


## [Unreleased]
### Added
- Add `FilterEngineBuilder::transaction_timeout`, which sets how long `Transaction::new` waits for
  the transaction lock before failing with `FWP_E_TIMEOUT`.
- Add `SubLayerBuilder::persistent`, for creating sublayers that persist across reboots.
- Add `delete_sublayer`, for deleting a sublayer by its GUID.

### Changed
- **Breaking**: Update `windows-sys` to 0.61. `GUID` is part of the public API, so dependents have
  to use the same `windows-sys` version.


## [0.0.7] - 2026-05-01
### Added
- Add `IpAddressConditionBuilder`, for matching on the local or remote IP address.


## [0.0.6] - 2026-05-01
### Added
- Add `ProviderBuilder` and `delete_provider`, for registering and removing WFP providers, together
  with `FilterBuilder::provider` and `SubLayerBuilder::provider` for associating filters and
  sublayers with a provider.
- Add `InterfaceConditionBuilder`, for matching on the local interface, either by LUID or by
  interface alias.
- Add `IcmpConditionBuilder`, for matching on ICMP type and code, and
  `ProtocolConditionBuilder::icmpv6`.


## [0.0.5] - 2026-04-10
### Added
- Add `FilterBuilder::weight`, together with `FilterWeight` and `WeightRange`, for controlling the
  order in which filters are evaluated within a sublayer.
- Add `FilterBuilder::lifetime` and `FilterLifetime`, making it possible to create persistent and
  boot-time filters.
- Add `FilterBuilder::guid`, for setting the filter's `filterKey`.
- Re-export `GUID` from the crate root, since it is part of the public API.


## [0.0.4] - 2026-04-01
### Changed
- **Breaking**: Derive application ID conditions from the file path using
  `FwpmGetAppIdFromFileName0` instead of passing the path as a string.
  `AppIdConditionBuilder::equal` now returns an `io::Result`.


## [0.0.3] - 2025-09-14
### Added
- Add `FilterEnumerator`, for enumerating the filters installed in a layer. Each `FilterEnumItem`
  exposes the filter's ID, GUID, provider, name and description.
- Add `delete_filter` and `delete_filter_by_guid`, for deleting filters by ID and by GUID.

### Fixed
- Fix cloned filter and sublayer builders keeping pointers into the original builder's name and
  description buffers. Adding a filter or sublayer from the clone could read freed memory.


## [0.0.2] - 2025-08-31
### Fixed
- Compile to an empty crate on non-Windows targets instead of failing to build.
- Build the docs.rs documentation for `x86_64-pc-windows-msvc`, so that the API is documented
  there.


## [0.0.1] - 2025-08-21
### Added
- Initial release.
