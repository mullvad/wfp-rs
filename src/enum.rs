//! Enumeration over WFP objects.

use crate::action::ActionType;
use crate::condition::Condition;
use crate::layer::Layer;
use crate::util::null_terminated_utf16_to_os_string;
use crate::{GUID, Transaction};

use std::ffi::OsString;
use std::io;
use std::marker::PhantomData;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_FLAG_TERMINATING, FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH,
    FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY, FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME,
    FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED, FWP_FILTER_ENUM_FLAG_SORTED,
    FWP_FILTER_ENUM_FULLY_CONTAINED, FWP_FILTER_ENUM_OVERLAPPING, FWP_FILTER_ENUM_TYPE,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER0, FWPM_SUBLAYER_ENUM_TEMPLATE0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FwpmSubLayerCreateEnumHandle0,
    FwpmSubLayerDestroyEnumHandle0, FwpmSubLayerEnum0,
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

    /// A safe, owning enumeration template, implemented by [`FilterEnumTemplate`] and
    /// [`SubLayerEnumTemplate`].
    ///
    /// This trait lives in a private module, so it cannot be named, implemented or called from
    /// outside the crate.
    pub trait EnumTemplate {
        /// The raw WFP enumeration template.
        type Raw;

        /// Calls `f` with the raw template.
        ///
        /// The raw template contains pointers into `self` and into temporaries owned by this
        /// method, so it is only valid for the duration of the call to `f`.
        fn with_raw<R>(&self, f: impl FnOnce(&Self::Raw) -> R) -> R;
    }

    /// A type of WFP object that can be enumerated, implemented by [`Filter`] and [`SubLayer`].
    ///
    /// This trait lives in a private module, so it cannot be named, implemented or called from
    /// outside the crate.
    pub trait EnumerableObject {
        /// The raw WFP structure returned by the enumeration API.
        type Object;

        /// The raw WFP enumeration template accepted by [`Self::CREATE_ENUM_HANDLE`].
        type Template;

        /// The safe enumeration template that restricts which objects are enumerated.
        type EnumTemplate: EnumTemplate<Raw = Self::Template>;

        /// The `FwpmXxxCreateEnumHandle0` function for this object type.
        const CREATE_ENUM_HANDLE: CreateEnumHandleFn<Self::Template>;

        /// The `FwpmXxxEnum0` function for this object type.
        const ENUM: EnumFn<Self::Object>;

        /// The `FwpmXxxDestroyEnumHandle0` function for this object type.
        const DESTROY_ENUM_HANDLE: DestroyEnumHandleFn;
    }
}

use private::{CreateEnumHandleFn, DestroyEnumHandleFn, EnumFn, EnumTemplate, EnumerableObject};

/// Selects filters ([`FWPM_FILTER0`]) for enumeration. See [`FilterEnumerator`].
///
/// This is a type-level tag; it has no values.
///
/// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
pub enum Filter {}

impl EnumerableObject for Filter {
    type Object = FWPM_FILTER0;
    type Template = FWPM_FILTER_ENUM_TEMPLATE0;
    type EnumTemplate = FilterEnumTemplate<FilterEnumTemplateHasLayer>;

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
    type EnumTemplate = SubLayerEnumTemplate;

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

/// Matches filters with any action type.
///
/// This corresponds to the `actionMask` value `0xFFFFFFFF` in [`FWPM_FILTER_ENUM_TEMPLATE0`],
/// documented as "ignore the filter's action type when enumerating". Note that the mask is *not*
/// allowed to be zero: only filters whose action type has at least one bit in common with the mask
/// are returned, so a zero mask returns nothing.
///
/// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
const ACTION_MASK_ANY: u32 = 0xFFFFFFFF;

/// Determines how the conditions of a [`FilterEnumTemplate`] are matched against the conditions of
/// each filter.
///
/// These correspond to the [`FWP_FILTER_ENUM_TYPE`] enumeration values.
///
/// [`FWP_FILTER_ENUM_TYPE`]: https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_filter_enum_type
#[repr(i32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FilterEnumType {
    /// Return only filters whose conditions are fully contained by the conditions in the template.
    ///
    /// Corresponds to `FWP_FILTER_ENUM_FULLY_CONTAINED`.
    #[default]
    FullyContained = FWP_FILTER_ENUM_FULLY_CONTAINED,
    /// Return all filters whose conditions overlap the conditions in the template.
    ///
    /// Corresponds to `FWP_FILTER_ENUM_OVERLAPPING`.
    Overlapping = FWP_FILTER_ENUM_OVERLAPPING,
}

/// Restricts which filters a [`FilterEnumerator`] returns.
///
/// This corresponds to the [`FWPM_FILTER_ENUM_TEMPLATE0`] structure. Filters can only be enumerated
/// one layer at a time, so [`Self::layer`] must be called before the template can be used. Apart
/// from the layer, a template matches every filter, and each method narrows down the filters that
/// are returned.
///
/// # Type Parameters
///
/// The type parameter tracks whether the required layer has been set:
/// - `LayerState`: Tracks whether a layer has been provided
///
/// # Example
///
/// ```no_run
/// use wfp::{
///     ActionType, FilterEngineBuilder, FilterEnumTemplate, FilterEnumerator, Layer, Transaction,
/// };
/// use std::io;
///
/// fn main() -> io::Result<()> {
///     let mut engine = FilterEngineBuilder::default().dynamic().open()?;
///     let t = Transaction::new(&mut engine)?;
///
///     // Blocking filters only, highest weight first
///     let template = FilterEnumTemplate::default()
///         .layer(Layer::ConnectV4)
///         .action(ActionType::Block)
///         .sorted();
///
///     let mut filter_enum = FilterEnumerator::with_template(&t, &template)?;
///
///     while let Some(filter) = filter_enum.next() {
///         let filter = filter?;
///         let name = filter.name();
///         println!("Name: {name:?}");
///     }
///
///     Ok(())
/// }
/// ```
///
/// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
#[derive(Clone)]
pub struct FilterEnumTemplate<LayerState> {
    layer_key: GUID,
    provider_key: Option<GUID>,
    enum_type: FilterEnumType,
    flags: u32,
    conditions: Vec<Condition>,
    /// `None` matches any action type. See [`ACTION_MASK_ANY`].
    action_mask: Option<u32>,

    _pd: PhantomData<LayerState>,
}

/// Type-level marker indicating that the layer to enumerate has not been set.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct FilterEnumTemplateMissingLayer;

/// Type-level marker indicating that the layer to enumerate has been set.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct FilterEnumTemplateHasLayer;

impl Default for FilterEnumTemplate<FilterEnumTemplateMissingLayer> {
    /// Creates a new filter enumeration template with no layer set.
    ///
    /// You must call [`FilterEnumTemplate::layer`] before the template can be passed to
    /// [`FilterEnumerator::with_template`].
    fn default() -> Self {
        FilterEnumTemplate {
            layer_key: GUID::default(),
            provider_key: None,
            enum_type: FilterEnumType::default(),
            flags: 0,
            conditions: Vec::new(),
            action_mask: None,
            _pd: PhantomData,
        }
    }
}

impl<LayerState> FilterEnumTemplate<LayerState> {
    /// Only return filters at the given layer.
    ///
    /// Filters are always enumerated one layer at a time; there is no way to enumerate the filters
    /// of every layer in a single pass. Create a [`FilterEnumerator`] without a template to
    /// enumerate the filters of every layer.
    ///
    /// This sets the `layerKey` field in the underlying [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn layer(self, layer: Layer) -> FilterEnumTemplate<FilterEnumTemplateHasLayer> {
        FilterEnumTemplate {
            layer_key: *layer.guid(),
            provider_key: self.provider_key,
            enum_type: self.enum_type,
            flags: self.flags,
            conditions: self.conditions,
            action_mask: self.action_mask,
            _pd: PhantomData,
        }
    }

    /// Only return filters belonging to the given provider.
    ///
    /// The GUID corresponds to the `providerKey` field of a provider created with
    /// [`ProviderBuilder`](crate::ProviderBuilder). If this is not set, filters from all providers
    /// are returned.
    ///
    /// This sets the `providerKey` field in the underlying [`FWPM_FILTER_ENUM_TEMPLATE0`]
    /// structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn provider(mut self, provider: GUID) -> Self {
        self.provider_key = Some(provider);
        self
    }

    /// Adds a condition that returned filters are matched against.
    ///
    /// How the conditions are matched is determined by [`Self::enum_type`]. If no conditions are
    /// added, all filters match.
    ///
    /// Duplicated conditions make the enumeration fail, according to the [`FWPM_FILTER_CONDITION0`]
    /// documentation.
    ///
    /// This adds an entry to the `filterCondition` array in the underlying
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_CONDITION0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Sets how the conditions added with [`Self::condition`] are matched.
    ///
    /// This sets the `enumType` field in the underlying [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn enum_type(mut self, enum_type: FilterEnumType) -> Self {
        self.enum_type = enum_type;
        self
    }

    /// Only return filters with the given action type.
    ///
    /// If this is called more than once, filters with any of the given action types are returned.
    /// If it is not called at all, the action type is ignored when enumerating.
    ///
    /// This sets the `actionMask` field in the underlying [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn action(mut self, action: ActionType) -> Self {
        // `actionMask` is matched bitwise against the action type. The `FWP_ACTION_*` constants
        // contain the `FWP_ACTION_FLAG_TERMINATING` bit, which both block and permit filters have,
        // so it has to be masked out to match on the action itself.
        let action_bits = action as u32 ^ FWP_ACTION_FLAG_TERMINATING;
        self.action_mask = Some(self.action_mask.unwrap_or(0) | action_bits);
        self
    }

    /// Only return the terminating filter with the highest weight.
    ///
    /// This sets the `FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH` bit in the `flags` field of the
    /// underlying [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn best_terminating_match(mut self) -> Self {
        self.flags |= FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH;
        self
    }

    /// Return the matching filters sorted by weight, from highest to lowest.
    ///
    /// This sets the `FWP_FILTER_ENUM_FLAG_SORTED` bit in the `flags` field of the underlying
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn sorted(mut self) -> Self {
        self.flags |= FWP_FILTER_ENUM_FLAG_SORTED;
        self
    }

    /// Only return boot-time filters.
    ///
    /// This makes [`Self::include_boottime`] and [`Self::include_disabled`] have no effect.
    ///
    /// This sets the `FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY` bit in the `flags` field of the
    /// underlying [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn boottime_only(mut self) -> Self {
        // TODO: Make mutually exclusive with include_bootime and include_disabled?
        self.flags |= FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY;
        self
    }

    /// Also return boot-time filters.
    ///
    /// This sets the `FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME` bit in the `flags` field of the
    /// underlying [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn include_boottime(mut self) -> Self {
        // TODO: Make mutually exclusive with boottime_only?
        self.flags |= FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME;
        self
    }

    /// Also return disabled filters.
    ///
    /// This sets the `FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED` bit in the `flags` field of the
    /// underlying [`FWPM_FILTER_ENUM_TEMPLATE0`] structure.
    ///
    /// [`FWPM_FILTER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
    pub fn include_disabled(mut self) -> Self {
        // TODO: Make mutually exclusive with boottime_only?
        self.flags |= FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
        self
    }
}

impl EnumTemplate for FilterEnumTemplate<FilterEnumTemplateHasLayer> {
    type Raw = FWPM_FILTER_ENUM_TEMPLATE0;

    fn with_raw<R>(&self, f: impl FnOnce(&Self::Raw) -> R) -> R {
        // The raw conditions have to be contiguous, so they are collected into a temporary array
        // that lives for as long as the raw template. The `Condition`s keep the data that the
        // conditions point to alive.
        let conditions: Vec<FWPM_FILTER_CONDITION0> = self
            .conditions
            .iter()
            .map(|condition| *condition.raw_condition())
            .collect();

        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            // SAFETY: The provider key is never mutated, and lives for as long as `self`
            providerKey: self
                .provider_key
                .as_ref()
                .map_or(ptr::null_mut(), |guid| ptr::from_ref(guid).cast_mut()),
            layerKey: self.layer_key,
            enumType: self.enum_type as FWP_FILTER_ENUM_TYPE,
            flags: self.flags,
            providerContextTemplate: ptr::null_mut(),
            numFilterConditions: u32::try_from(conditions.len()).unwrap(),
            filterCondition: if conditions.is_empty() {
                ptr::null_mut()
            } else {
                // SAFETY: The conditions are never mutated, and live for as long as the template
                conditions.as_ptr().cast_mut()
            },
            actionMask: self.action_mask.unwrap_or(ACTION_MASK_ANY),
            calloutKey: ptr::null_mut(),
        };

        f(&template)
    }
}

/// Restricts which sublayers a [`SubLayerEnumerator`] returns.
///
/// This corresponds to the [`FWPM_SUBLAYER_ENUM_TEMPLATE0`] structure. A default template matches
/// every sublayer.
///
/// # Example
///
/// ```no_run
/// use wfp::{FilterEngineBuilder, GUID, SubLayerEnumTemplate, SubLayerEnumerator, Transaction};
/// use std::io;
///
/// fn main() -> io::Result<()> {
///     let provider = GUID::from_u128(0x11111111_2222_3333_4444_555555555555);
///
///     let mut engine = FilterEngineBuilder::default().dynamic().open()?;
///     let t = Transaction::new(&mut engine)?;
///
///     let template = SubLayerEnumTemplate::default().provider(provider);
///     let mut sublayer_enum = SubLayerEnumerator::with_template(&t, &template)?;
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
///
/// [`FWPM_SUBLAYER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer_enum_template0
#[derive(Clone, Default)]
pub struct SubLayerEnumTemplate {
    provider_key: Option<GUID>,
}

impl SubLayerEnumTemplate {
    /// Only return sublayers belonging to the given provider.
    ///
    /// The GUID corresponds to the `providerKey` field of a provider created with
    /// [`ProviderBuilder`](crate::ProviderBuilder). If this is not set, sublayers from all
    /// providers are returned.
    ///
    /// This sets the `providerKey` field in the underlying [`FWPM_SUBLAYER_ENUM_TEMPLATE0`]
    /// structure.
    ///
    /// [`FWPM_SUBLAYER_ENUM_TEMPLATE0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer_enum_template0
    pub fn provider(mut self, provider: GUID) -> Self {
        self.provider_key = Some(provider);
        self
    }
}

impl EnumTemplate for SubLayerEnumTemplate {
    type Raw = FWPM_SUBLAYER_ENUM_TEMPLATE0;

    fn with_raw<R>(&self, f: impl FnOnce(&Self::Raw) -> R) -> R {
        let template = FWPM_SUBLAYER_ENUM_TEMPLATE0 {
            // SAFETY: The provider key is never mutated, and lives for as long as `self`
            providerKey: self
                .provider_key
                .as_ref()
                .map_or(ptr::null_mut(), |guid| ptr::from_ref(guid).cast_mut()),
        };

        f(&template)
    }
}

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
    /// Creates a new enumerator over all objects, for the given filter engine.
    ///
    /// This calls `FwpmFilterCreateEnumHandle0` or `FwpmSubLayerCreateEnumHandle0` to create an
    /// enumeration handle that can be used to iterate over WFP objects.
    ///
    /// Use [`Self::with_template`] to enumerate a subset of the objects.
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
        // SAFETY: A null enumeration template enumerates all objects
        unsafe { Self::create(transaction, ptr::null()) }
    }

    /// Creates a new enumerator over the objects matching `template`, for the given filter engine.
    ///
    /// This calls `FwpmFilterCreateEnumHandle0` or `FwpmSubLayerCreateEnumHandle0` to create an
    /// enumeration handle that can be used to iterate over WFP objects.
    ///
    /// # Arguments
    ///
    /// * `transaction` - A transaction
    /// * `template` - A [`FilterEnumTemplate`] or [`SubLayerEnumTemplate`] restricting which
    ///   objects are enumerated
    ///
    /// # Returns
    ///
    /// Returns a new `Enumerator` on success, or an `io::Error` if the
    /// enumeration handle could not be created.
    pub fn with_template(
        transaction: &'a Transaction<'a>,
        template: &T::EnumTemplate,
    ) -> io::Result<Self> {
        // SAFETY: The raw template is valid for the duration of the closure
        template.with_raw(|raw| unsafe { Self::create(transaction, raw) })
    }

    /// Creates a new enumerator using the given raw enumeration template.
    ///
    /// # Safety
    ///
    /// `template` must either be null, or point to a valid enumeration template that remains valid
    /// for the duration of the call.
    unsafe fn create(
        transaction: &'a Transaction<'a>,
        template: *const T::Template,
    ) -> io::Result<Self> {
        let mut enum_handle = HANDLE::default();

        // SAFETY:
        // - engine.as_raw_handle() returns a valid engine handle
        // - template is null or valid, as guaranteed by the caller
        // - enum_handle is a valid pointer to receive the handle
        let status = unsafe {
            (T::CREATE_ENUM_HANDLE)(
                transaction.engine.as_raw_handle(),
                template,
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::PortConditionBuilder;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    };

    const PROVIDER: GUID = GUID::from_u128(0x11111111_2222_3333_4444_555555555555);
    const LAYER: Layer = Layer::ConnectV4;

    fn assert_guid_eq(actual: &GUID, expected: &GUID) {
        assert_eq!(actual.data1, expected.data1);
        assert_eq!(actual.data2, expected.data2);
        assert_eq!(actual.data3, expected.data3);
        assert_eq!(actual.data4, expected.data4);
    }

    /// A filter template that only sets the required layer must match every filter in that layer.
    /// In particular, the action mask must match any action, since a zeroed mask matches nothing.
    #[test]
    fn test_default_filter_template_matches_everything() {
        FilterEnumTemplate::default().layer(LAYER).with_raw(|raw| {
            assert_eq!(raw.actionMask, ACTION_MASK_ANY);
            assert!(raw.providerKey.is_null());
            assert_guid_eq(&raw.layerKey, LAYER.guid());
            assert_eq!(raw.enumType, FWP_FILTER_ENUM_FULLY_CONTAINED);
            assert_eq!(raw.flags, 0);
            assert_eq!(raw.numFilterConditions, 0);
            assert!(raw.filterCondition.is_null());
            assert!(raw.providerContextTemplate.is_null());
            assert!(raw.calloutKey.is_null());
        });
    }

    #[test]
    fn test_default_sublayer_template_matches_everything() {
        SubLayerEnumTemplate::default().with_raw(|raw| assert!(raw.providerKey.is_null()));
    }

    #[test]
    fn test_filter_template_provider() {
        FilterEnumTemplate::default()
            .layer(LAYER)
            .provider(PROVIDER)
            .with_raw(|raw| {
                // SAFETY: The provider key is non-null and points to the GUID in the template
                assert_guid_eq(unsafe { &*raw.providerKey }, &PROVIDER);
            });
    }

    #[test]
    fn test_sublayer_template_provider() {
        SubLayerEnumTemplate::default()
            .provider(PROVIDER)
            .with_raw(|raw| {
                // SAFETY: The provider key is non-null and points to the GUID in the template
                assert_guid_eq(unsafe { &*raw.providerKey }, &PROVIDER);
            });
    }

    /// The action mask is matched bitwise against the action type, so the terminating bit that all
    /// action types have must not be part of it.
    #[test]
    fn test_filter_template_action_mask() {
        FilterEnumTemplate::default()
            .layer(LAYER)
            .action(ActionType::Block)
            .with_raw(|raw| {
                assert_eq!(
                    raw.actionMask,
                    FWP_ACTION_BLOCK ^ FWP_ACTION_FLAG_TERMINATING
                );
                assert_eq!(raw.actionMask & FWP_ACTION_FLAG_TERMINATING, 0);
            });
    }

    /// Setting several actions must match filters with any of them.
    #[test]
    fn test_filter_template_multiple_action_masks() {
        FilterEnumTemplate::default()
            .layer(LAYER)
            .action(ActionType::Block)
            .action(ActionType::Permit)
            .with_raw(|raw| {
                let expected = (FWP_ACTION_BLOCK ^ FWP_ACTION_FLAG_TERMINATING)
                    | (FWP_ACTION_PERMIT ^ FWP_ACTION_FLAG_TERMINATING);
                assert_eq!(raw.actionMask, expected);
            });
    }

    #[test]
    fn test_filter_template_flags_and_enum_type() {
        FilterEnumTemplate::default()
            .layer(LAYER)
            .enum_type(FilterEnumType::Overlapping)
            .sorted()
            .include_disabled()
            .with_raw(|raw| {
                assert_eq!(raw.enumType, FWP_FILTER_ENUM_OVERLAPPING);
                assert_eq!(
                    raw.flags,
                    FWP_FILTER_ENUM_FLAG_SORTED | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED
                );
            });
    }

    #[test]
    fn test_filter_template_conditions() {
        let template = FilterEnumTemplate::default()
            .layer(LAYER)
            .condition(PortConditionBuilder::remote().equal(80).build())
            .condition(PortConditionBuilder::local().equal(443).build());

        template.with_raw(|raw| {
            assert_eq!(raw.numFilterConditions, 2);

            // SAFETY: The template has two conditions, so the array contains two elements
            let conditions = unsafe { std::slice::from_raw_parts(raw.filterCondition, 2) };

            for (raw_condition, condition) in conditions.iter().zip(&template.conditions) {
                assert_guid_eq(&raw_condition.fieldKey, &condition.raw_condition().fieldKey);
                assert_eq!(raw_condition.matchType, condition.raw_condition().matchType);
            }
        });
    }
}
