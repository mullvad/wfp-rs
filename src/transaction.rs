//! Transaction creation and management

use std::io;
use std::mem;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionAbort0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionBegin0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionCommit0;

use crate::engine::FilterEngine;

/// Represents a transactional context for filter operations.
///
/// Transactions ensure that multiple filter operations are applied atomically.
/// If any operation fails, the entire transaction can be rolled back, leaving
/// the filter state unchanged.
///
/// The transaction holds a mutable reference to the `FilterEngine`, preventing
/// other transactions on the engine until this one is completed or dropped.
///
/// # Drop behavior
///
/// If a `Transaction` is dropped without being explicitly committed, it will
/// automatically attempt to abort, rolling back any changes made during the
/// transaction. If this fails, the error is logged.
///
/// If you wish to explicitly abort a transaction and handle any error, call
/// [`Transaction::abort`].
pub struct Transaction<'a> {
    pub(crate) engine: &'a mut FilterEngine,
}

// SAFETY: Crossing thread-boundaries is fine
unsafe impl Send for Transaction<'_> {}

impl<'a> Transaction<'a> {
    /// Creates a new transaction for the given filter engine.
    ///
    /// This method calls [`FwpmTransactionBegin0`] to start a new transaction context.
    ///
    /// [`FwpmTransactionBegin0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
    pub fn new(engine: &'a mut FilterEngine) -> io::Result<Self> {
        // TODO: read-only
        // SAFETY:
        // - engine.as_raw_handle() returns a valid engine handle from FilterEngine
        // - 0 is a valid flags parameter (no special transaction flags)
        // - The engine handle remains valid for the lifetime of the transaction
        let status = unsafe { FwpmTransactionBegin0(engine.as_raw_handle(), 0) };
        // FIXME: handle other errors
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(Self { engine })
    }

    /// Commits all changes made during this transaction.
    ///
    /// Once committed, all filter operations performed within this transaction
    /// become permanent and visible to the system. This method calls [`FwpmTransactionCommit0`].
    ///
    /// [`FwpmTransactionCommit0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0
    pub fn commit(self) -> io::Result<()> {
        // SAFETY:
        // - self.engine.as_raw_handle() returns a valid engine handle
        // - A transaction was successfully started with FwpmTransactionBegin0
        // - This consumes self, preventing multiple commits of the same transaction
        let status = unsafe { FwpmTransactionCommit0(self.engine.as_raw_handle()) };
        // FIXME: handle other errors
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        mem::forget(self);

        Ok(())
    }

    /// Explicitly aborts the transaction, rolling back all changes.
    ///
    /// This method allows you to explicitly roll back a transaction without
    /// relying on the automatic abort behavior when the transaction is dropped.
    /// This method calls [`FwpmTransactionAbort0`].
    ///
    /// [`FwpmTransactionAbort0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionabort0
    pub fn abort(self) -> io::Result<()> {
        self.abort_inner()?;

        mem::forget(self);

        Ok(())
    }

    fn abort_inner(&self) -> io::Result<()> {
        // SAFETY:
        // - self.engine.as_raw_handle() returns a valid engine handle
        // - A transaction was successfully started with FwpmTransactionBegin0
        // - FwpmTransactionAbort0 is safe to call multiple times on the same transaction
        let status = unsafe { FwpmTransactionAbort0(self.engine.as_raw_handle()) };
        // FIXME: handle other errors
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(())
    }
}

impl<'a> Drop for Transaction<'a> {
    fn drop(&mut self) {
        if let Err(err) = self.abort_inner() {
            log::error!("Failed to abort dropped transaction: {err}");
        }
    }
}
