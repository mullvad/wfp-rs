//! Filter creation and management for the Windows Filtering Platform.

mod weight;

pub use weight::*;

use std::ffi::OsStr;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::STATUS_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_EMPTY, FWP_UINT8, FWP_UINT64, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_BOOTTIME,
    FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmFilterDeleteByKey0,
};

use crate::GUID;
use crate::action::ActionType;
use crate::condition::Condition;
use crate::layer::Layer;
use crate::transaction::Transaction;
use crate::util::string_to_null_terminated_utf16;

/// Builder for creating Windows Filtering Platform filters.
///
/// This builder uses the type system to ensure that all required fields
/// (name, description, and action) are provided before a filter can be created.
/// The underlying filter is represented by the [`FWPM_FILTER0`] structure.
///
/// # Type Parameters
///
/// The type parameters track which required fields have been set:
/// - `Name`: Tracks whether a name has been provided
/// - `Action`: Tracks whether an action has been provided
///
/// # Example
///
/// ```no_run
/// use wfp::{FilterBuilder, ActionType, Layer, Transaction, FilterEngine};
/// use std::io;
///
/// fn create_filter(transaction: &Transaction) -> io::Result<()> {
///     FilterBuilder::default()
///         .name("My Filter")
///         .description("Blocks suspicious traffic")
///         .action(ActionType::Block)
///         .layer(Layer::ConnectV4)
///         .add(transaction)?;
///     Ok(())
/// }
/// ```
///
/// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
#[derive(Clone)]
pub struct FilterBuilder<Name, Action> {
    filter: FWPM_FILTER0,

    display_data_name_buffer: Arc<[u16]>,
    display_data_desc_buffer: Arc<[u16]>,
    provider_key: Option<Arc<GUID>>,
    conditions: Vec<Condition>,
    weight_value: u64,

    _pd: std::marker::PhantomData<(Name, Action)>,
}

/// Type-level marker indicating that a filter name has not been set.
#[doc(hidden)]
pub struct FilterBuilderMissingName;

/// Type-level marker indicating that a filter name has been set.
#[doc(hidden)]
pub struct FilterBuilderHasName;

/// Type-level marker indicating that a filter action has not been set.
#[doc(hidden)]
#[derive(Default)]
pub struct FilterBuilderMissingAction;

/// Type-level marker indicating that a filter action has been set.
#[doc(hidden)]
pub struct FilterBuilderHasAction;

impl Default for FilterBuilder<FilterBuilderMissingName, FilterBuilderMissingAction> {
    /// Creates a new filter builder with no fields set.
    ///
    /// You must call `name()`, `description()`, and `action()` before the filter
    /// can be added to a transaction.
    fn default() -> Self {
        FilterBuilder {
            filter: Default::default(),
            display_data_name_buffer: Default::default(),
            display_data_desc_buffer: Default::default(),
            provider_key: None,
            conditions: Default::default(),
            weight_value: 0,
            _pd: Default::default(),
        }
    }
}

impl<Name, Action> FilterBuilder<Name, Action> {
    /// Sets the display name for the filter.
    ///
    /// The name should explain the filter's purpose.
    ///
    /// This sets the `displayData.name` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// # Returns
    ///
    /// Returns a new builder instance with the name field set.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn name(mut self, name: impl AsRef<OsStr>) -> FilterBuilder<FilterBuilderHasName, Action> {
        self.display_data_name_buffer = string_to_null_terminated_utf16(name);
        // SAFETY: The data is never mutated
        self.filter.displayData.name = self.display_data_name_buffer.as_ptr() as *mut _;
        FilterBuilder {
            filter: self.filter,
            display_data_name_buffer: self.display_data_name_buffer,
            display_data_desc_buffer: self.display_data_desc_buffer,
            provider_key: self.provider_key,
            conditions: self.conditions,
            weight_value: self.weight_value,
            _pd: std::marker::PhantomData,
        }
    }

    /// Sets the description for the filter.
    ///
    /// The description should explain in more detail the filter's purpose.
    ///
    /// This sets the `displayData.description` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn description(mut self, desc: impl AsRef<OsStr>) -> FilterBuilder<Name, Action> {
        self.display_data_desc_buffer = string_to_null_terminated_utf16(desc);
        // SAFETY: The data is never mutated
        self.filter.displayData.description = self.display_data_desc_buffer.as_ptr() as *mut _;
        FilterBuilder {
            filter: self.filter,
            display_data_name_buffer: self.display_data_name_buffer,
            display_data_desc_buffer: self.display_data_desc_buffer,
            provider_key: self.provider_key,
            conditions: self.conditions,
            weight_value: self.weight_value,
            _pd: std::marker::PhantomData,
        }
    }

    /// Sets the action to take when the filter matches network traffic.
    ///
    /// This sets the `action.type` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn action(mut self, action: ActionType) -> FilterBuilder<Name, FilterBuilderHasAction> {
        self.filter.action.r#type = action as u32;
        FilterBuilder {
            filter: self.filter,
            display_data_name_buffer: self.display_data_name_buffer,
            display_data_desc_buffer: self.display_data_desc_buffer,
            provider_key: self.provider_key,
            conditions: self.conditions,
            weight_value: self.weight_value,
            _pd: std::marker::PhantomData,
        }
    }

    /// Sets the GUID that uniquely identifies this filter.
    ///
    /// If not set, the system assigns a GUID automatically.
    ///
    /// This sets the `filterKey` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn guid(mut self, guid: GUID) -> FilterBuilder<Name, Action> {
        self.filter.filterKey = guid;
        self
    }

    /// Sets the network layer at which the filter operates.
    ///
    /// This sets the `layerKey` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn layer(mut self, layer: Layer) -> FilterBuilder<Name, Action> {
        self.filter.layerKey = *layer.guid();
        self
    }

    /// Sets the sublayer at which the filter operates.
    ///
    /// If not set, the default sublayer is used.
    ///
    /// This sets the `subLayerKey` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn sublayer(mut self, sublayer: GUID) -> FilterBuilder<Name, Action> {
        self.filter.subLayerKey = sublayer;
        self
    }

    /// Attaches the filter to a provider.
    ///
    /// This sets the `providerKey` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn provider(mut self, guid: GUID) -> FilterBuilder<Name, Action> {
        let key = Arc::new(guid);
        // SAFETY: The data is never mutated; the Arc keeps the GUID alive as long as `self` lives.
        self.filter.providerKey = Arc::as_ptr(&key) as *mut _;
        self.provider_key = Some(key);
        self
    }

    /// Sets the weight (priority) of the filter within its sublayer.
    ///
    /// Higher weight means the filter is evaluated first. See the
    /// [Filter Arbitration] documentation for details.
    ///
    /// This sets the `weight` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [Filter Arbitration]: https://docs.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn weight(mut self, weight: impl Into<FilterWeight>) -> FilterBuilder<Name, Action> {
        match weight.into() {
            FilterWeight::Auto => {
                self.filter.weight.r#type = FWP_EMPTY;
            }
            FilterWeight::Range(range) => {
                self.filter.weight.r#type = FWP_UINT8;
                self.filter.weight.Anonymous.uint8 = range.get();
            }
            FilterWeight::Exact(val) => {
                self.weight_value = val;
                self.filter.weight.r#type = FWP_UINT64;
                // The pointer is set in add() since self may move after this call.
            }
        }
        self
    }

    /// Sets the lifetime of the filter.
    ///
    /// This sets the `flags` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    pub fn lifetime(mut self, lifetime: FilterLifetime) -> FilterBuilder<Name, Action> {
        self.filter.flags &= !(FWPM_FILTER_FLAG_BOOTTIME | FWPM_FILTER_FLAG_PERSISTENT);
        match lifetime {
            FilterLifetime::Default => {}
            FilterLifetime::Boottime => {
                self.filter.flags |= FWPM_FILTER_FLAG_BOOTTIME;
            }
            FilterLifetime::Persistent => {
                self.filter.flags |= FWPM_FILTER_FLAG_PERSISTENT;
            }
        }
        self
    }

    /// Adds a condition to the filter.
    ///
    /// Conditions specify criteria that network traffic must match for the filter
    /// to apply. Multiple conditions can be added, and all must match for the
    /// filter to trigger (logical AND). Conditions of the same type
    /// (e.g. [`crate::ConditionField::RemoteAddress`]) are combined using logical OR.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wfp::{FilterBuilder, PortConditionBuilder, ConditionField, MatchType, ActionType, Layer};
    ///
    /// let filter = FilterBuilder::default()
    ///     .name("Block port 80")
    ///     .description("Blocks HTTP traffic")
    ///     .action(ActionType::Block)
    ///     .layer(Layer::ConnectV4)
    ///     .condition(
    ///         PortConditionBuilder::remote()
    ///             .equal(80)
    ///             .build()
    ///     );
    /// ```
    pub fn condition(mut self, condition: Condition) -> FilterBuilder<Name, Action> {
        self.conditions.push(condition);
        self
    }
}

impl FilterBuilder<FilterBuilderHasName, FilterBuilderHasAction> {
    /// Adds the configured filter to a transaction.
    ///
    /// This method is only available when all required fields (name, description,
    /// and action) have been set on the builder.
    ///
    /// It calls [`FwpmFilterAdd0`] to add the filter to the engine.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if the filter could not be added.
    ///
    /// [`FwpmFilterAdd0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0
    pub fn add<'a>(&self, transaction: &Transaction<'a>) -> io::Result<()> {
        // Convert conditions to FWPM_FILTER_CONDITION0 array
        let fwpm_conditions: Vec<FWPM_FILTER_CONDITION0> = self
            .conditions
            .iter()
            .map(|condition| *condition.raw_condition())
            .collect();

        // Create a mutable copy of the filter to set condition fields
        let mut filter = self.filter;

        if !fwpm_conditions.is_empty() {
            filter.numFilterConditions = u32::try_from(fwpm_conditions.len()).unwrap();
            // SAFETY: The conditions are never actually mutated
            filter.filterCondition = fwpm_conditions.as_ptr() as *mut _;
        }

        // Set the weight pointer for Exact weights. This must be done here
        // rather than in weight() because the builder may have moved since then.
        if filter.weight.r#type == FWP_UINT64 {
            // SAFETY: The data is not mutated despite the type.
            filter.weight.Anonymous.uint64 = &self.weight_value as *const u64 as *mut u64;
        }

        // SAFETY:
        // - &filter is a valid pointer to a properly initialized FWPM_FILTER0 structure
        // - All pointers and data have the same lifetime as `self` (at least)
        // - NULL security descriptor and filter ID pointers are acceptable
        let status = unsafe {
            FwpmFilterAdd0(
                transaction.engine.as_raw_handle(),
                &filter,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(())
    }
}

/// Controls the lifetime of a filter.
///
/// Boot-time and persistent filters are mutually exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FilterLifetime {
    /// Filter lives as long as the engine session (default).
    #[default]
    Default,
    /// Filter is active only during boot, before BFE starts but as soon as `tcpip.sys` starts.
    ///
    /// This corresponds to [`FWPM_FILTER_FLAG_BOOTTIME`].
    ///
    /// [`FWPM_FILTER_FLAG_BOOTTIME`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    Boottime,
    /// Filter persists across reboots.
    ///
    /// This corresponds to [`FWPM_FILTER_FLAG_PERSISTENT`].
    ///
    /// [`FWPM_FILTER_FLAG_PERSISTENT`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    Persistent,
}

/// Delete a filter by its ID.
///
/// The ID corresponds to the `filterId` field in the underlying [`FWPM_FILTER0`] structure.
///
/// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
pub fn delete_filter<'a>(transaction: &Transaction<'a>, id: u64) -> io::Result<()> {
    // SAFETY: The handle and ID are valid
    let status = unsafe { FwpmFilterDeleteById0(transaction.engine.as_raw_handle(), id) };
    if status != STATUS_SUCCESS as u32 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Delete a filter by its GUID.
///
/// The GUID corresponds to the `filterKey` field in the underlying [`FWPM_FILTER0`] structure.
///
/// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
pub fn delete_filter_by_guid<'a>(transaction: &Transaction<'a>, guid: &GUID) -> io::Result<()> {
    // SAFETY: The handle and GUID are valid
    let status = unsafe { FwpmFilterDeleteByKey0(transaction.engine.as_raw_handle(), guid) };
    if status != STATUS_SUCCESS as u32 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}
