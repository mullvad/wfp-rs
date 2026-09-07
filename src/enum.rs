//! Enumeration over WFP objects.

use crate::util::null_terminated_utf16_to_os_string;
use crate::{FilterAction, FilterWeight, GUID, Layer, Transaction, WeightRange};

use std::ffi::OsString;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_EMPTY, FWP_UINT8, FWP_UINT64, FWP_VALUE0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER0,
    FWPM_SUBLAYER_ENUM_TEMPLATE0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDestroyEnumHandle0, FwpmSubLayerEnum0,
};

mod private {
    use super::*;

    /// The `FwpmXxxCreateEnumHandle0` signature, where `T` is the enumeration template.
    pub type CreateEnumHandleFn<T> =
        unsafe extern "system" fn(HANDLE, *const T, *mut HANDLE) -> u32;

    /// The `FwpmXxxEnum0` signature, where `T` is the enumerated object.
    pub type EnumFn<T> =
        unsafe extern "system" fn(HANDLE, HANDLE, u32, *mut *mut *mut T, *mut u32) -> u32;

    /// The `FwpmXxxDestroyEnumHandle0` signature.
    pub type DestroyEnumHandleFn = unsafe extern "system" fn(HANDLE, HANDLE) -> u32;

    /// A type of WFP object that can be enumerated, implemented by [`Filter`] and [`SubLayer`].
    ///
    /// This trait lives in a private module, so it cannot be named, implemented or called from
    /// outside the crate.
    pub trait EnumerableObject {
        /// The raw WFP structure returned by the enumeration API.
        type Object;

        /// The raw WFP enumeration template accepted by [`Self::CREATE_ENUM_HANDLE`].
        type Template;

        /// The `FwpmXxxCreateEnumHandle0` function for this object type.
        const CREATE_ENUM_HANDLE: CreateEnumHandleFn<Self::Template>;

        /// The `FwpmXxxEnum0` function for this object type.
        const ENUM: EnumFn<Self::Object>;

        /// The `FwpmXxxDestroyEnumHandle0` function for this object type.
        const DESTROY_ENUM_HANDLE: DestroyEnumHandleFn;
    }
}

use private::{CreateEnumHandleFn, DestroyEnumHandleFn, EnumFn, EnumerableObject};

/// Selects filters ([`FWPM_FILTER0`]) for enumeration. See [`FilterEnumerator`].
///
/// This is a type-level tag; it has no values.
///
/// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
pub enum Filter {}

impl EnumerableObject for Filter {
    type Object = FWPM_FILTER0;
    type Template = FWPM_FILTER_ENUM_TEMPLATE0;

    const CREATE_ENUM_HANDLE: CreateEnumHandleFn<Self::Template> = FwpmFilterCreateEnumHandle0;
    const ENUM: EnumFn<Self::Object> = FwpmFilterEnum0;
    const DESTROY_ENUM_HANDLE: DestroyEnumHandleFn = FwpmFilterDestroyEnumHandle0;
}

/// Selects sublayers ([`FWPM_SUBLAYER0`]) for enumeration. See [`SubLayerEnumerator`].
///
/// This is a type-level tag; it has no values.
///
/// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
pub enum SubLayer {}

impl EnumerableObject for SubLayer {
    type Object = FWPM_SUBLAYER0;
    type Template = FWPM_SUBLAYER_ENUM_TEMPLATE0;

    const CREATE_ENUM_HANDLE: CreateEnumHandleFn<Self::Template> = FwpmSubLayerCreateEnumHandle0;
    const ENUM: EnumFn<Self::Object> = FwpmSubLayerEnum0;
    const DESTROY_ENUM_HANDLE: DestroyEnumHandleFn = FwpmSubLayerDestroyEnumHandle0;
}

/// An iterator over filters.
///
/// This struct wraps the [`FwpmFilterEnum0`] API.
///
/// [`FwpmFilterEnum0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
///
/// # Example
///
/// ```no_run
/// use wfp::{FilterEngineBuilder, FilterEnumerator, Transaction};
/// use std::io;
///
/// fn main() -> io::Result<()> {
///     let mut engine = FilterEngineBuilder::default().dynamic().open()?;
///     let t = Transaction::new(&mut engine)?;
///
///     let mut filter_enum = FilterEnumerator::new(&t)?;
///
///     while let Some(filter) = filter_enum.next() {
///         let filter = filter?;
///         let id = filter.id();
///         println!("Name: {id}");
///     }
///
///     Ok(())
/// }
/// ```
pub type FilterEnumerator<'a> = Enumerator<'a, Filter>;

/// A WFP filter
///
/// # Example
///
/// Inspecting the filters that belong to a particular provider and sublayer:
///
/// ```no_run
/// use wfp::{FilterEngineBuilder, FilterEnumerator, GUID, Transaction};
/// use std::io;
///
/// const MY_PROVIDER: GUID = GUID::from_u128(0x0f0f0f0f_1111_2222_3333_444455556666);
/// const MY_SUBLAYER: GUID = GUID::from_u128(0x0f0f0f0f_1234_5678_9abc_def012345678);
///
/// /// `GUID` does not implement `PartialEq`.
/// fn guid_eq(left: &GUID, right: &GUID) -> bool {
///     left.data1 == right.data1
///         && left.data2 == right.data2
///         && left.data3 == right.data3
///         && left.data4 == right.data4
/// }
///
/// fn main() -> io::Result<()> {
///     let mut engine = FilterEngineBuilder::default().dynamic().open()?;
///     let t = Transaction::new(&mut engine)?;
///
///     let mut filter_enum = FilterEnumerator::new(&t)?;
///
///     while let Some(filter) = filter_enum.next() {
///         let filter = filter?;
///
///         // Enumeration returns every filter on the system, so skip the ones that are not ours
///         let is_ours = filter
///             .provider()
///             .is_some_and(|guid| guid_eq(&guid, &MY_PROVIDER))
///             && guid_eq(&filter.sublayer(), &MY_SUBLAYER);
///         if !is_ours {
///             continue;
///         }
///
///         println!("{:?}", filter.name());
///         println!("  layer:            {:?}", filter.layer());
///         println!("  action:           {:?}", filter.action());
///         println!("  weight:           {:?}", filter.weight());
///         println!("  effective weight: {:?}", filter.effective_weight());
///         println!("  conditions:       {}", filter.num_conditions());
///     }
///
///     Ok(())
/// }
/// ```
pub type FilterEnumItem<'a> = EnumItem<'a, Filter>;

/// An iterator over sublayers.
///
/// This struct wraps the [`FwpmSubLayerEnum0`] API.
///
/// [`FwpmSubLayerEnum0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayerenum0
///
/// # Example
///
/// ```no_run
/// use wfp::{FilterEngineBuilder, SubLayerEnumerator, Transaction};
/// use std::io;
///
/// fn main() -> io::Result<()> {
///     let mut engine = FilterEngineBuilder::default().dynamic().open()?;
///     let t = Transaction::new(&mut engine)?;
///
///     let mut sublayer_enum = SubLayerEnumerator::new(&t)?;
///
///     while let Some(sublayer) = sublayer_enum.next() {
///         let sublayer = sublayer?;
///         let name = sublayer.name();
///         println!("Name: {name:?}");
///     }
///
///     Ok(())
/// }
/// ```
pub type SubLayerEnumerator<'a> = Enumerator<'a, SubLayer>;

/// A WFP sublayer
pub type SubLayerEnumItem<'a> = EnumItem<'a, SubLayer>;

/// An iterator over WFP objects of type `T`.
///
/// See [`FilterEnumerator`] and [`SubLayerEnumerator`].
pub struct Enumerator<'a, T: EnumerableObject> {
    transaction: &'a Transaction<'a>,
    enum_handle: HANDLE,
    exhausted: bool,
    current_entries: *mut *mut T::Object,
    current_num_entries: u32,
    current_index: u32,
}

impl<'a, T: EnumerableObject> Enumerator<'a, T> {
    /// Creates a new enumerator for the given filter engine.
    ///
    /// This calls `FwpmFilterCreateEnumHandle0` or `FwpmSubLayerCreateEnumHandle0` to create an
    /// enumeration handle that can be used to iterate over WFP objects.
    ///
    /// # Arguments
    ///
    /// * `transaction` - A transaction
    ///
    /// # Returns
    ///
    /// Returns a new `Enumerator` on success, or an `io::Error` if the
    /// enumeration handle could not be created.
    pub fn new(transaction: &'a Transaction<'a>) -> io::Result<Self> {
        let mut enum_handle = HANDLE::default();

        // SAFETY:
        // - engine.as_raw_handle() returns a valid engine handle
        // - a null enumeration template enumerates all objects
        // - enum_handle is a valid pointer to receive the handle
        let status = unsafe {
            (T::CREATE_ENUM_HANDLE)(
                transaction.engine.as_raw_handle(),
                ptr::null(),
                &mut enum_handle,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(Self {
            transaction,
            enum_handle,
            exhausted: false,
            current_entries: ptr::null_mut(),
            current_num_entries: 0,
            current_index: 0,
        })
    }

    /// Gets the next object from the enumeration, or `None` if iteration is complete.
    ///
    /// This method returns an `EnumItem` that borrows from the enumerator,
    /// preventing further calls to `next()` until the returned `EnumItem` is dropped.
    ///
    /// If an error occurs, an error is returned, and future calls to `next` return `None`.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<io::Result<EnumItem<'_, T>>> {
        const NUM_ENTRIES: u32 = 50;

        if self.exhausted {
            return None;
        }

        // The current batch is used up, so fetch the next one
        if self.current_index == self.current_num_entries {
            let prev_num_entries = self.current_num_entries;

            self.free_current_entries();

            // If the previous entries were fewer than requested num, we are done
            if prev_num_entries != 0 && prev_num_entries < NUM_ENTRIES {
                self.exhausted = true;
                return None;
            }

            // SAFETY:
            // - self.engine.as_raw_handle() returns a valid engine handle
            // - self.enum_handle is a valid enumeration handle
            // - entries and num_entries are valid pointers
            let status = unsafe {
                (T::ENUM)(
                    self.transaction.engine.as_raw_handle(),
                    self.enum_handle,
                    NUM_ENTRIES,
                    &mut self.current_entries,
                    &mut self.current_num_entries,
                )
            };
            self.current_index = 0;

            match status {
                // The batch contains at least one object; fall through and return it
                ERROR_SUCCESS if self.current_num_entries > 0 => {}
                ERROR_SUCCESS | ERROR_NO_MORE_ITEMS => {
                    self.exhausted = true;
                    return None;
                }
                _ => {
                    self.exhausted = true;
                    return Some(Err(io::Error::from_raw_os_error(status as i32)));
                }
            }
        }

        // SAFETY: The entries are valid and `current_index` is less than the total number of
        //         entries. The returned `EnumItem` borrows `*self` for as long as it exists, so
        //         the entries cannot be freed until it has been dropped.
        let idx = usize::try_from(self.current_index).unwrap();
        let object = unsafe { &**self.current_entries.add(idx) };
        self.current_index += 1;

        Some(Ok(EnumItem { object }))
    }

    /// Frees the current entries if they exist.
    fn free_current_entries(&mut self) {
        if !self.current_entries.is_null() {
            // SAFETY: current_entries was allocated by the enumeration function
            unsafe { FwpmFreeMemory0((&mut self.current_entries) as *mut _ as *mut _) };
            self.current_entries = ptr::null_mut();
            self.current_num_entries = 0;
            self.current_index = 0;
        }
    }
}

impl<T: EnumerableObject> Drop for Enumerator<'_, T> {
    fn drop(&mut self) {
        // Free any current entries before destroying the handle
        self.free_current_entries();

        // SAFETY:
        // - self.engine.as_raw_handle() returns a valid engine handle
        // - self.enum_handle is a valid enumeration handle created by `T::CREATE_ENUM_HANDLE`
        // - This is called exactly once during drop
        unsafe {
            (T::DESTROY_ENUM_HANDLE)(self.transaction.engine.as_raw_handle(), self.enum_handle);
        }
    }
}

/// A WFP object returned by an [`Enumerator`].
///
/// The item borrows the enumerator it came from, so the enumerator cannot be advanced or dropped
/// while the item is alive.
///
/// See [`FilterEnumItem`] and [`SubLayerEnumItem`].
pub struct EnumItem<'a, T: EnumerableObject> {
    object: &'a T::Object,
}

impl FilterEnumItem<'_> {
    /// Return the filter ID.
    ///
    /// This corresponds to the `filterId` field in the underlying [`FWPM_FILTER0`] structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn id(&self) -> u64 {
        self.object.filterId
    }

    /// Return the object name, if set.
    ///
    /// This corresponds to `displayData.name` in the underlying [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn name(&self) -> Option<OsString> {
        // SAFETY: If non-null, the string is null-terminated
        unsafe { null_terminated_utf16_to_os_string(self.object.displayData.name) }
    }

    /// Return the object description, if set.
    ///
    /// This corresponds to `displayData.description` in the underlying [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn description(&self) -> Option<OsString> {
        // SAFETY: If non-null, the string is null-terminated
        unsafe { null_terminated_utf16_to_os_string(self.object.displayData.description) }
    }

    /// Return the object GUID.
    ///
    /// This corresponds to the `filterKey` field in [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn guid(&self) -> GUID {
        self.object.filterKey
    }

    /// Return the object provider, if set.
    ///
    /// This corresponds to the `providerKey` field in [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn provider(&self) -> Option<GUID> {
        let provider_key = self.object.providerKey;
        if provider_key.is_null() {
            None
        } else {
            // SAFETY: The provider contains no pointers, and is non-null.
            Some(unsafe { *provider_key })
        }
    }

    /// Return the layer the filter is attached to, or `None` if it is not one of the layers named
    /// by [`Layer`].
    ///
    /// Enumeration returns every filter on the system, most of which sit at layers that this
    /// crate cannot build filters for. Use [`Self::layer_guid`] to read those.
    ///
    /// This corresponds to the `layerKey` field in [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn layer(&self) -> Option<Layer> {
        Layer::from_guid(&self.object.layerKey)
    }

    /// Return the GUID of the layer the filter is attached to.
    ///
    /// Unlike [`Self::layer`], this is available for every layer, including those that [`Layer`]
    /// does not name.
    ///
    /// This corresponds to the `layerKey` field in [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn layer_guid(&self) -> GUID {
        self.object.layerKey
    }

    /// Return the GUID of the sublayer the filter is attached to.
    ///
    /// This corresponds to the `subLayerKey` field in [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn sublayer(&self) -> GUID {
        self.object.subLayerKey
    }

    /// Return the weight that was requested when the filter was added, or `None` if it is not one
    /// of the value types that [`FilterWeight`] describes.
    ///
    /// This is the weight as specified by whoever added the filter, which may be
    /// [`FilterWeight::Auto`]. It is *not* the weight that decides evaluation order; see
    /// [`Self::effective_weight`] for that.
    ///
    /// This corresponds to the `weight` field in [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn weight(&self) -> Option<FilterWeight> {
        let weight = &self.object.weight;
        match weight.r#type {
            FWP_EMPTY => Some(FilterWeight::Auto),
            FWP_UINT8 => {
                // SAFETY: The value is tagged FWP_UINT8, so `uint8` is the active union field.
                let raw = unsafe { weight.Anonymous.uint8 };
                WeightRange::try_from(raw).ok().map(FilterWeight::Range)
            }
            FWP_UINT64 => {
                // SAFETY: The FWP_VALUE0 type matches the value when set by WFP.
                unsafe { uint64_value(weight) }.map(FilterWeight::Exact)
            }
            _ => None,
        }
    }

    /// Return the weight that the Base Filtering Engine resolved for the filter, or `None` if it
    /// is not a `FWP_UINT64` value.
    ///
    /// Filters within a sublayer are evaluated in order of decreasing effective weight, so this
    /// is the weight to compare when reasoning about filter arbitration. See the
    /// [Filter Arbitration] documentation for details.
    ///
    /// This corresponds to the `effectiveWeight` field in [`FWPM_FILTER0`].
    ///
    /// [Filter Arbitration]: https://docs.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn effective_weight(&self) -> Option<u64> {
        // SAFETY: The FWP_VALUE0 type matches the value when set by WFP.
        unsafe { uint64_value(&self.object.effectiveWeight) }
    }

    /// Return the action taken when the filter matches network traffic.
    ///
    /// This corresponds to the `action.type` field in [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn action(&self) -> FilterAction {
        FilterAction::from_raw(self.object.action.r#type)
    }

    /// Return the number of conditions that traffic must match for the filter to apply.
    ///
    /// This corresponds to the `numFilterConditions` field in [`FWPM_FILTER0`].
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn num_conditions(&self) -> u32 {
        self.object.numFilterConditions
    }
}

impl SubLayerEnumItem<'_> {
    /// Return the sublayer weight (priority).
    ///
    /// This corresponds to the `weight` field in the underlying [`FWPM_SUBLAYER0`] structure.
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn weight(&self) -> u16 {
        self.object.weight
    }

    /// Return whether the sublayer is persistent, i.e. survives a Base Filtering Engine restart.
    ///
    /// This corresponds to the `FWPM_SUBLAYER_FLAG_PERSISTENT` bit in the `flags` field of the
    /// underlying [`FWPM_SUBLAYER0`] structure.
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn persistent(&self) -> bool {
        (self.object.flags & FWPM_SUBLAYER_FLAG_PERSISTENT) != 0
    }

    /// Return the object name, if set.
    ///
    /// This corresponds to `displayData.name` in the underlying [`FWPM_SUBLAYER0`]
    /// structure.
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn name(&self) -> Option<OsString> {
        // SAFETY: If non-null, the string is null-terminated
        unsafe { null_terminated_utf16_to_os_string(self.object.displayData.name) }
    }

    /// Return the object description, if set.
    ///
    /// This corresponds to `displayData.description` in the underlying [`FWPM_SUBLAYER0`]
    /// structure.
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn description(&self) -> Option<OsString> {
        // SAFETY: If non-null, the string is null-terminated
        unsafe { null_terminated_utf16_to_os_string(self.object.displayData.description) }
    }

    /// Return the object GUID.
    ///
    /// This corresponds to the `subLayerKey` field in [`FWPM_SUBLAYER0`].
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn guid(&self) -> GUID {
        self.object.subLayerKey
    }

    /// Return the object provider, if set.
    ///
    /// This corresponds to the `providerKey` field in [`FWPM_SUBLAYER0`].
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn provider(&self) -> Option<GUID> {
        let provider_key = self.object.providerKey;
        if provider_key.is_null() {
            None
        } else {
            // SAFETY: The provider contains no pointers, and is non-null.
            Some(unsafe { *provider_key })
        }
    }
}

/// Read the `u64` out of `value`, or `None` if it is not a `FWP_UINT64` or the pointer is null.
///
/// For `FWP_UINT64` the value is not stored inline: the `uint64` union field is a pointer to the
/// actual value.
///
/// # Safety
///
/// If `value` is tagged `FWP_UINT64`, its `uint64` pointer must be null or point to a live `u64`.
unsafe fn uint64_value(value: &FWP_VALUE0) -> Option<u64> {
    if value.r#type != FWP_UINT64 {
        return None;
    }
    // SAFETY: The value is tagged FWP_UINT64, so `uint64` is the active union field.
    let ptr = unsafe { value.Anonymous.uint64 };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: The pointer is non-null and points to a live u64, per the safety requirements.
    Some(unsafe { *ptr })
}
