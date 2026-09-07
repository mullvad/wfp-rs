//! Core types and enums for the Windows Filtering Platform wrapper.

use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_CALLOUT_INSPECTION, FWP_ACTION_CALLOUT_TERMINATING,
    FWP_ACTION_CALLOUT_UNKNOWN, FWP_ACTION_CONTINUE, FWP_ACTION_NONE, FWP_ACTION_NONE_NO_MATCH,
    FWP_ACTION_PERMIT, FWP_ACTION_TYPE,
};

/// Specifies the action to take when a filter matches network traffic.
///
/// These correspond to the [`FWP_ACTION_TYPE`] enumeration values.
///
/// # Example
///
/// ```
/// use wfp::ActionType;
///
/// let block_action = ActionType::Block;
/// let permit_action = ActionType::Permit;
/// ```
///
/// [`FWP_ACTION_TYPE`]: https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_action_type
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionType {
    /// Block the network traffic that matches the filter.
    Block = FWP_ACTION_BLOCK,
    /// Allow the network traffic that matches the filter to proceed.
    Permit = FWP_ACTION_PERMIT,
}

/// The action carried by a filter that was read back from the filter engine.
///
/// `FilterAction` covers every [`FWP_ACTION_TYPE`] value that enumeration can return,
/// including the callout actions and the values that only ever
/// appear as classification results. Unrecognized values are preserved as
/// [`FilterAction::Unknown`].
///
/// See the `action` getter on [`FilterEnumItem`].
///
/// # Example
///
/// ```
/// use wfp::{ActionType, FilterAction};
///
/// assert_eq!(FilterAction::from(ActionType::Block), FilterAction::Block);
/// ```
///
/// [`FWP_ACTION_TYPE`]: https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_action_type
/// [`FilterEnumItem`]: crate::FilterEnumItem
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterAction {
    /// Block the network traffic that matches the filter.
    ///
    /// Corresponds to `FWP_ACTION_BLOCK`.
    Block,
    /// Allow the network traffic that matches the filter to proceed.
    ///
    /// Corresponds to `FWP_ACTION_PERMIT`.
    Permit,
    /// Invoke a terminating callout, which returns a block or permit decision.
    ///
    /// Corresponds to `FWP_ACTION_CALLOUT_TERMINATING`.
    CalloutTerminating,
    /// Invoke a non-terminating callout, which inspects traffic but never blocks or permits it.
    ///
    /// Corresponds to `FWP_ACTION_CALLOUT_INSPECTION`.
    CalloutInspection,
    /// Invoke a callout that may or may not return a block or permit decision.
    ///
    /// Corresponds to `FWP_ACTION_CALLOUT_UNKNOWN`.
    CalloutUnknown,
    /// Continue to the next filter, if any.
    ///
    /// Corresponds to `FWP_ACTION_CONTINUE`.
    Continue,
    /// No action was taken.
    ///
    /// Corresponds to `FWP_ACTION_NONE`.
    None,
    /// No action was taken, and no filter matched.
    ///
    /// Corresponds to `FWP_ACTION_NONE_NO_MATCH`.
    NoneNoMatch,
    /// An action that this crate does not recognize, with the raw `FWP_ACTION_TYPE` value.
    Unknown(u32),
}

impl FilterAction {
    /// Decode a raw `FWP_ACTION_TYPE` value.
    ///
    /// This never fails; unrecognized values become [`FilterAction::Unknown`].
    pub(crate) fn from_raw(raw: FWP_ACTION_TYPE) -> Self {
        match raw {
            FWP_ACTION_BLOCK => Self::Block,
            FWP_ACTION_PERMIT => Self::Permit,
            FWP_ACTION_CALLOUT_TERMINATING => Self::CalloutTerminating,
            FWP_ACTION_CALLOUT_INSPECTION => Self::CalloutInspection,
            FWP_ACTION_CALLOUT_UNKNOWN => Self::CalloutUnknown,
            FWP_ACTION_CONTINUE => Self::Continue,
            FWP_ACTION_NONE => Self::None,
            FWP_ACTION_NONE_NO_MATCH => Self::NoneNoMatch,
            other => Self::Unknown(other),
        }
    }
}

impl From<ActionType> for FilterAction {
    fn from(action: ActionType) -> Self {
        match action {
            ActionType::Block => Self::Block,
            ActionType::Permit => Self::Permit,
        }
    }
}
