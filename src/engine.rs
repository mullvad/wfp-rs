//! Filter engine management for the Windows Filtering Platform.

use std::io;
use std::mem;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::RawHandle;
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::STATUS_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION_FLAG_DYNAMIC;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_SESSION0, FwpmEngineOpen0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

/// Builder for creating a Windows Filtering Platform engine session.
///
/// This builder allows you to configure session parameters before opening
/// a connection to the filter engine using the [`FWPM_SESSION0`] structure.
///
/// # Example
///
/// ```no_run
/// use wfp::FilterEngineBuilder;
/// use std::io;
///
/// fn main() -> io::Result<()> {
///     let engine = FilterEngineBuilder::default()
///         .dynamic()
///         .open()?;
///     Ok(())
/// }
/// ```
///
/// [`FWPM_SESSION0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
pub struct FilterEngineBuilder {
    session: FWPM_SESSION0,
}

// SAFETY: Crossing thread-boundaries is fine
unsafe impl Send for FilterEngineBuilder {}

impl Default for FilterEngineBuilder {
    fn default() -> Self {
        Self {
            // SAFETY: FWPM_SESSION0 is a C struct that is designed to be zero-initialized.
            // All fields have valid zero representations, and the Windows API expects
            // zero-initialized sessions to use default values.
            session: unsafe { mem::zeroed() },
        }
    }
}

impl FilterEngineBuilder {
    /// Opens a connection to the Windows Filtering Platform engine.
    ///
    /// This method calls the [`FwpmEngineOpen0`] function to establish a session
    /// with the filter engine.
    ///
    /// # Returns
    ///
    /// Returns a `FilterEngine` instance on success, or an error if the connection could not
    /// be established.
    ///
    /// [`FwpmEngineOpen0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
    pub fn open(self) -> io::Result<FilterEngine> {
        let mut handle: HANDLE = ptr::null_mut();

        // SAFETY:
        // - All parameters are valid: null pointers are acceptable for serverName and authInfo
        // - RPC_C_AUTHN_DEFAULT is a valid authentication service constant
        // - self.session is a properly initialized FWPM_SESSION0 structure
        // - handle is a valid mutable pointer to receive the engine handle
        let result = unsafe {
            FwpmEngineOpen0(
                ptr::null_mut(),
                RPC_C_AUTHN_DEFAULT as u32,
                ptr::null_mut(),
                &self.session,
                &mut handle,
            )
        };
        if result != STATUS_SUCCESS as u32 {
            return Err(io::Error::last_os_error());
        }
        Ok(FilterEngine { handle })
    }

    /// Configures the session to use dynamic filters.
    ///
    /// Dynamic filters are automatically removed when the session is closed,
    /// making them ideal for temporary filtering rules that don't need to
    /// persist when the session ends.
    ///
    /// This sets the [`FWPM_SESSION_FLAG_DYNAMIC`] flag.
    ///
    /// [`FWPM_SESSION_FLAG_DYNAMIC`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
    pub fn dynamic(mut self) -> Self {
        self.session.flags |= FWPM_SESSION_FLAG_DYNAMIC;
        self
    }

    /// Sets how long a call to [`Transaction::new`] waits for the transaction
    /// lock before failing with `FWP_E_TIMEOUT`.
    ///
    /// [`Duration::ZERO`] lets the Base Filtering Engine pick its own default
    /// timeout, which is also what happens if this is never called. Durations
    /// are truncated to whole milliseconds, and anything longer than
    /// `u32::MAX` milliseconds (roughly 49 days) is clamped to that.
    ///
    /// This sets the `txnWaitTimeoutInMSec` field in the underlying
    /// [`FWPM_SESSION0`] structure.
    ///
    /// [`Transaction::new`]: crate::Transaction::new
    /// [`FWPM_SESSION0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
    pub fn transaction_timeout(mut self, timeout: Duration) -> Self {
        self.session.txnWaitTimeoutInMSec = timeout.as_millis().try_into().unwrap_or(u32::MAX);
        self
    }
}

/// Represents an active connection to the Windows Filtering Platform engine.
///
/// This struct manages the lifetime of a WFP engine session and provides
/// the context needed for filter operations. The engine automatically
/// closes the session when dropped using [`FwpmEngineClose0`].
///
/// `FilterEngine` is `Send` and can be moved between threads, but is not `Sync`.
/// This prevents multiple concurrent transactions on the same engine at compile-time, which
/// otherwise result in runtime errors.
///
/// [`FwpmEngineClose0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineclose0
pub struct FilterEngine {
    handle: HANDLE,
}

// SAFETY: Crossing thread-boundaries is fine
unsafe impl Send for FilterEngine {}

impl AsRawHandle for FilterEngine {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle
    }
}

impl Drop for FilterEngine {
    fn drop(&mut self) {
        // SAFETY:
        // - self.handle is a valid engine handle obtained from FwpmEngineOpen0
        // - We are the sole owner of this handle (FilterEngine is not Clone)
        // - This is called exactly once during drop, preventing double-free
        unsafe { FwpmEngineClose0(self.handle) };
    }
}
