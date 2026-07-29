//! Provider creation and management.

use std::ffi::OsStr;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
};

use crate::GUID;
use crate::transaction::Transaction;
use crate::util::string_to_null_terminated_utf16;

/// Builder for creating Windows Filtering Platform providers.
///
/// The underlying provider is represented by the [`FWPM_PROVIDER0`] structure.
///
/// This builder uses the type system to ensure that the required `name` field
/// is provided before a provider can be added.
///
/// # Type Parameters
///
/// - `Name`: Tracks whether a name has been provided.
///
/// # Example
///
/// ```no_run
/// use wfp::{GUID, ProviderBuilder, Transaction};
/// use std::io;
///
/// fn create_provider(transaction: &Transaction) -> io::Result<()> {
///     let provider_guid = GUID::from_u128(0x11111111_2222_3333_4444_555555555555);
///     ProviderBuilder::default()
///         .name("My Provider")
///         .description("Groups filters owned by my application")
///         .guid(provider_guid)
///         .add(transaction)?;
///     Ok(())
/// }
/// ```
///
/// # Persistent providers
///
/// [`ProviderBuilder::persistent`] marks the provider (and any persistent
/// objects under it) as surviving a Base Filtering Engine restart. Persistent
/// state survives reboots and must be cleaned up explicitly with
/// [`delete_provider`].
///
/// [`FWPM_PROVIDER0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
#[derive(Clone)]
pub struct ProviderBuilder<Name> {
    provider: FWPM_PROVIDER0,

    display_data_name_buffer: Arc<[u16]>,
    display_data_desc_buffer: Arc<[u16]>,
    service_name_buffer: Option<Arc<[u16]>>,

    _pd: std::marker::PhantomData<Name>,
}

/// Type-level marker indicating that a provider name has not been set.
#[doc(hidden)]
pub struct ProviderBuilderMissingName;

/// Type-level marker indicating that a provider name has been set.
#[doc(hidden)]
pub struct ProviderBuilderHasName;

impl Default for ProviderBuilder<ProviderBuilderMissingName> {
    /// Creates a new provider builder with no fields set.
    ///
    /// You must call `name()` before the provider can be added to a
    /// transaction.
    ///
    /// This corresponds to the type [`FWPM_PROVIDER0`].
    ///
    /// [`FWPM_PROVIDER0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
    fn default() -> ProviderBuilder<ProviderBuilderMissingName> {
        ProviderBuilder {
            provider: Default::default(),
            display_data_name_buffer: Default::default(),
            display_data_desc_buffer: Default::default(),
            service_name_buffer: None,
            _pd: Default::default(),
        }
    }
}

impl<Name> ProviderBuilder<Name> {
    /// Sets the display name for the provider.
    ///
    /// This sets the `displayData.name` field in the underlying
    /// [`FWPM_PROVIDER0`] structure.
    ///
    /// [`FWPM_PROVIDER0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
    pub fn name(mut self, name: impl AsRef<OsStr>) -> ProviderBuilder<ProviderBuilderHasName> {
        self.display_data_name_buffer = string_to_null_terminated_utf16(name);
        // SAFETY: The data is never mutated
        self.provider.displayData.name = self.display_data_name_buffer.as_ptr() as *mut _;
        ProviderBuilder {
            provider: self.provider,
            display_data_name_buffer: self.display_data_name_buffer,
            display_data_desc_buffer: self.display_data_desc_buffer,
            service_name_buffer: self.service_name_buffer,

            _pd: std::marker::PhantomData,
        }
    }

    /// Sets the description for the provider.
    ///
    /// This sets the `displayData.description` field in the underlying
    /// [`FWPM_PROVIDER0`] structure.
    ///
    /// [`FWPM_PROVIDER0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
    pub fn description(mut self, desc: impl AsRef<OsStr>) -> ProviderBuilder<Name> {
        self.display_data_desc_buffer = string_to_null_terminated_utf16(desc);
        // SAFETY: The data is never mutated
        self.provider.displayData.description = self.display_data_desc_buffer.as_ptr() as *mut _;
        self
    }

    /// Sets a custom GUID for the provider.
    ///
    /// If not set, Windows will automatically generate a GUID for the
    /// provider. In practice you almost always want to set a stable GUID so
    /// that filters and sublayers can reference it.
    ///
    /// This sets the `providerKey` field in the underlying [`FWPM_PROVIDER0`]
    /// structure.
    ///
    /// [`FWPM_PROVIDER0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
    pub fn guid(mut self, guid: GUID) -> ProviderBuilder<Name> {
        self.provider.providerKey = guid;
        self
    }

    /// Marks the provider as persistent.
    ///
    /// Persistent providers - and persistent filters and sublayers under them -
    /// survive a Base Filtering Engine restart. Persistent state survives
    /// reboots and must be cleaned up explicitly with [`delete_provider`].
    ///
    /// This sets the `FWPM_PROVIDER_FLAG_PERSISTENT` bit in the `flags` field
    /// of the underlying [`FWPM_PROVIDER0`] structure.
    ///
    /// [`FWPM_PROVIDER0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
    pub fn persistent(mut self) -> ProviderBuilder<Name> {
        self.provider.flags |= FWPM_PROVIDER_FLAG_PERSISTENT;
        self
    }

    /// Sets the optional Windows service name associated with the provider.
    ///
    /// This sets the `serviceName` field in the underlying [`FWPM_PROVIDER0`]
    /// structure.
    ///
    /// [`FWPM_PROVIDER0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
    pub fn service_name(mut self, service: impl AsRef<OsStr>) -> ProviderBuilder<Name> {
        let buf: Arc<[u16]> = string_to_null_terminated_utf16(service);
        // SAFETY: The data is never mutated
        self.provider.serviceName = buf.as_ptr() as *mut _;
        self.service_name_buffer = Some(buf);
        self
    }
}

impl ProviderBuilder<ProviderBuilderHasName> {
    /// Adds the configured provider to a transaction.
    ///
    /// This method is only available when the required `name` field has been
    /// set on the builder.
    ///
    /// It calls [`FwpmProviderAdd0`] to add the provider to the engine.
    ///
    /// [`FwpmProviderAdd0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmprovideradd0
    pub fn add<'a>(&self, transaction: &Transaction<'a>) -> io::Result<()> {
        // SAFETY:
        // - transaction.engine.as_raw_handle() returns a valid engine handle
        // - &self.provider is a valid pointer to a properly initialized FWPM_PROVIDER0 structure
        // - The required name field has been set by the type system
        // - The display data and service name buffers are kept alive by self,
        //   ensuring all string pointers remain valid for the duration of the call
        // - NULL security descriptor pointer is acceptable (uses default security)
        let status = unsafe {
            FwpmProviderAdd0(
                transaction.engine.as_raw_handle(),
                &self.provider,
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(())
    }
}

/// Delete a provider by its GUID.
///
/// The GUID corresponds to the `providerKey` field in the underlying
/// [`FWPM_PROVIDER0`] structure.
///
/// This calls [`FwpmProviderDeleteByKey0`]. It returns
/// `FWP_E_PROVIDER_REFERENCED` (surfaced as an [`io::Error`]) if any filter or
/// sublayer is still attached to the provider; remove those first.
///
/// [`FWPM_PROVIDER0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
/// [`FwpmProviderDeleteByKey0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmproviderdeletebykey0
pub fn delete_provider<'a>(transaction: &Transaction<'a>, guid: &GUID) -> io::Result<()> {
    // SAFETY: The handle and GUID are valid
    let status = unsafe { FwpmProviderDeleteByKey0(transaction.engine.as_raw_handle(), guid) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}
