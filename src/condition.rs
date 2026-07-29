//! Filter condition creation and management.

use std::ffi::OsStr;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_MATCH_GREATER, FWP_MATCH_GREATER_OR_EQUAL,
    FWP_MATCH_LESS, FWP_MATCH_LESS_OR_EQUAL, FWP_MATCH_RANGE, FWP_UINT8, FWP_UINT16, FWP_UINT32,
    FWP_UINT64, FWP_UNICODE_STRING_TYPE, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
};

use crate::GUID;
use crate::blob::{OwnedByteBlob, app_id_from_filename};
use crate::util::string_to_null_terminated_utf16;

// In `fwpmu.h`, `FWPM_CONDITION_ICMP_TYPE` and `FWPM_CONDITION_ICMP_CODE` are
// `#define`d as aliases for `FWPM_CONDITION_IP_LOCAL_PORT` and
// `FWPM_CONDITION_IP_REMOTE_PORT` respectively.
const FWPM_CONDITION_ICMP_TYPE: GUID = FWPM_CONDITION_IP_LOCAL_PORT;
const FWPM_CONDITION_ICMP_CODE: GUID = FWPM_CONDITION_IP_REMOTE_PORT;

/// Typed builder for port-based conditions.
///
/// This builder enforces that only valid port numbers (u16) can be used as values,
/// providing compile-time type safety for port-related filtering.
///
/// # Example
///
/// ```no_run
/// use wfp::{PortConditionBuilder, ConditionField, MatchType};
///
/// // Block traffic to port 80
/// let condition = PortConditionBuilder::remote()
///     .equal(80)
///     .build();
/// ```
#[derive(Clone)]
pub struct PortConditionBuilder<Value> {
    builder: ConditionBuilder,
    _pd: std::marker::PhantomData<Value>,
}

/// Type-state marker indicating the port value has not been set.
#[doc(hidden)]
pub struct PortConditionBuilderMissingValue;

/// Type-state marker indicating the port value has been set.
#[doc(hidden)]
pub struct PortConditionBuilderHasValue;

impl PortConditionBuilder<PortConditionBuilderMissingValue> {
    /// Creates a remote port condition.
    pub fn remote() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::RemotePort),
            _pd: std::marker::PhantomData,
        }
    }

    /// Creates a local port condition.
    pub fn local() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::LocalPort),
            _pd: std::marker::PhantomData,
        }
    }
}

impl<Value> PortConditionBuilder<Value> {
    /// Creates a condition that matches the exact port number.
    pub fn equal(self, port: u16) -> PortConditionBuilder<PortConditionBuilderHasValue> {
        PortConditionBuilder {
            builder: self.builder.match_type(MatchType::Equal).value_u16(port),
            _pd: std::marker::PhantomData,
        }
    }
}

impl PortConditionBuilder<PortConditionBuilderHasValue> {
    /// Builds the condition.
    ///
    /// This method is only available when a port value has been set with `equal()`.
    pub fn build(self) -> Condition {
        self.builder.build().expect("condition has value")
    }
}

/// Typed builder for protocol-based conditions.
///
/// This builder enforces that only valid protocol numbers (u32) can be used as values,
/// providing compile-time type safety for protocol-related filtering.
///
/// # Example
///
/// ```no_run
/// use wfp::{ProtocolConditionBuilder, MatchType};
///
/// // Block TCP traffic (protocol 6)
/// let tcp_condition = ProtocolConditionBuilder::tcp().build();
///
/// // Block UDP traffic (protocol 17)
/// let udp_condition = ProtocolConditionBuilder::udp().build();
/// ```
#[derive(Clone)]
pub struct ProtocolConditionBuilder {
    builder: ConditionBuilder,
}

impl ProtocolConditionBuilder {
    /// Creates a condition that matches TCP traffic (protocol 6).
    pub fn tcp() -> Self {
        Self::new().equal(6)
    }

    /// Creates a condition that matches UDP traffic (protocol 17).
    pub fn udp() -> Self {
        Self::new().equal(17)
    }

    /// Creates a condition that matches ICMP traffic (protocol 1).
    pub fn icmp() -> Self {
        Self::new().equal(1)
    }

    /// Creates a condition that matches IPv6-ICMP traffic (protocol 58).
    pub fn icmpv6() -> Self {
        Self::new().equal(58)
    }

    /// Creates a new protocol condition builder.
    fn new() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::Protocol),
        }
    }

    /// Creates a condition that matches the exact protocol number.
    fn equal(self, protocol: u8) -> Self {
        Self {
            builder: self.builder.match_type(MatchType::Equal).value_u8(protocol),
        }
    }

    /// Builds the condition.
    pub fn build(self) -> Condition {
        self.builder.build().expect("all values are set")
    }
}

impl Default for ProtocolConditionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed builder for ICMP conditions.
///
/// # Example
///
/// ```no_run
/// use wfp::{IcmpConditionBuilder, MatchType};
///
/// // Match echo request (type 8)
/// let condition = IcmpConditionBuilder::r#type()
///     .equal(8)
///     .build();
///
/// // Match ICMP code 0
/// let condition = IcmpConditionBuilder::code()
///     .equal(0)
///     .build();
/// ```
#[derive(Clone)]
pub struct IcmpConditionBuilder<Value> {
    builder: ConditionBuilder,
    _pd: std::marker::PhantomData<Value>,
}

/// Type-state marker indicating the ICMP value has not been set.
#[doc(hidden)]
pub struct IcmpConditionBuilderMissingValue;

/// Type-state marker indicating the ICMP value has been set.
#[doc(hidden)]
pub struct IcmpConditionBuilderHasValue;

impl IcmpConditionBuilder<IcmpConditionBuilderMissingValue> {
    /// Creates an ICMP type condition.
    pub fn r#type() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::IcmpType),
            _pd: std::marker::PhantomData,
        }
    }

    /// Creates an ICMP code condition.
    pub fn code() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::IcmpCode),
            _pd: std::marker::PhantomData,
        }
    }
}

impl<Value> IcmpConditionBuilder<Value> {
    /// Creates a condition that matches the exact value.
    pub fn equal(self, value: u8) -> IcmpConditionBuilder<IcmpConditionBuilderHasValue> {
        IcmpConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::Equal)
                .value_u16(value.into()),
            _pd: std::marker::PhantomData,
        }
    }

    /// Creates a condition that matches values greater than the given value.
    pub fn greater(self, value: u8) -> IcmpConditionBuilder<IcmpConditionBuilderHasValue> {
        IcmpConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::Greater)
                .value_u16(value.into()),
            _pd: std::marker::PhantomData,
        }
    }

    /// Creates a condition that matches values less than the given value.
    pub fn less(self, value: u8) -> IcmpConditionBuilder<IcmpConditionBuilderHasValue> {
        IcmpConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::Less)
                .value_u16(value.into()),
            _pd: std::marker::PhantomData,
        }
    }

    /// Creates a condition that matches values greater than or equal to the given value.
    pub fn greater_or_equal(self, value: u8) -> IcmpConditionBuilder<IcmpConditionBuilderHasValue> {
        IcmpConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::GreaterOrEqual)
                .value_u16(value.into()),
            _pd: std::marker::PhantomData,
        }
    }

    /// Creates a condition that matches values less than or equal to the given value.
    pub fn less_or_equal(self, value: u8) -> IcmpConditionBuilder<IcmpConditionBuilderHasValue> {
        IcmpConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::LessOrEqual)
                .value_u16(value.into()),
            _pd: std::marker::PhantomData,
        }
    }
}

impl IcmpConditionBuilder<IcmpConditionBuilderHasValue> {
    /// Builds the condition.
    ///
    /// This method is only available when a value has been set.
    pub fn build(self) -> Condition {
        self.builder.build().expect("condition has value")
    }
}

/// Typed builder for application ID conditions.
///
/// These are used for application-based filtering.
///
/// # Example
///
/// ```ignore
/// use wfp::AppIdConditionBuilder;
///
/// // Block traffic from a specific application
/// let app_condition = AppIdConditionBuilder::default()
///     .equal(r"C:\Program Files\MyApp\app.exe")?
///     .build();
/// ```
pub struct AppIdConditionBuilder<Value> {
    builder: ConditionBuilder,
    _pd: std::marker::PhantomData<Value>,
}

/// Type-state marker indicating the app ID value has not been set.
#[doc(hidden)]
pub struct AppIdConditionBuilderMissingValue;

/// Type-state marker indicating the app ID value has been set.
#[doc(hidden)]
pub struct AppIdConditionBuilderHasValue;

impl AppIdConditionBuilder<AppIdConditionBuilderMissingValue> {
    /// Creates a new application ID condition builder.
    pub fn new() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::AppId),
            _pd: std::marker::PhantomData,
        }
    }
}

impl<Value> AppIdConditionBuilder<Value> {
    /// Creates a condition that matches the exact application path.
    pub fn equal(
        self,
        app_path: impl AsRef<OsStr>,
    ) -> io::Result<AppIdConditionBuilder<AppIdConditionBuilderHasValue>> {
        let byte_blob = app_id_from_filename(app_path)?;

        Ok(AppIdConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::Equal)
                .value_byte_blob(byte_blob),
            _pd: std::marker::PhantomData,
        })
    }
}

impl AppIdConditionBuilder<AppIdConditionBuilderHasValue> {
    /// Builds the condition.
    ///
    /// This method is only available when an application path has been set with `equal()`.
    pub fn build(self) -> Condition {
        self.builder.build().expect("condition has value")
    }
}

impl Default for AppIdConditionBuilder<AppIdConditionBuilderMissingValue> {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed builder for interface (LUID) conditions.
///
/// Builds a condition that matches the local interface a connection is bound to,
/// corresponding to `FWPM_CONDITION_IP_LOCAL_INTERFACE`.
///
/// # Example
///
/// ```ignore
/// use wfp::InterfaceConditionBuilder;
///
/// // Match traffic bound to the "Test" interface
/// let condition = InterfaceConditionBuilder::local()
///     .alias("Test")?
///     .build();
/// ```
pub struct InterfaceConditionBuilder<Value> {
    builder: ConditionBuilder,
    _pd: std::marker::PhantomData<Value>,
}

/// Type-state marker indicating the interface value has not been set.
#[doc(hidden)]
pub struct InterfaceConditionBuilderMissingValue;

/// Type-state marker indicating the interface value has been set.
#[doc(hidden)]
pub struct InterfaceConditionBuilderHasValue;

impl InterfaceConditionBuilder<InterfaceConditionBuilderMissingValue> {
    /// Creates a local interface condition (`FWPM_CONDITION_IP_LOCAL_INTERFACE`).
    pub fn local() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::LocalInterface),
            _pd: std::marker::PhantomData,
        }
    }
}

impl<Value> InterfaceConditionBuilder<Value> {
    /// Creates a condition that matches the interface with the given alias.
    ///
    /// The alias is resolved to a LUID using [`ConvertInterfaceAliasToLuid`].
    /// Returns `Err` if the interface does not exist.
    ///
    /// [`ConvertInterfaceAliasToLuid`]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfacealiastoluid
    pub fn alias(
        self,
        alias: impl AsRef<OsStr>,
    ) -> io::Result<InterfaceConditionBuilder<InterfaceConditionBuilderHasValue>> {
        let wide_alias: Vec<u16> = string_to_null_terminated_utf16(alias);
        let mut luid = NET_LUID_LH::default();

        // SAFETY: Passing a null-terminated UTF-16 string and a valid pointer to NET_LUID_LH.
        let status = unsafe { ConvertInterfaceAliasToLuid(wide_alias.as_ptr(), &mut luid) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        // SAFETY: NET_LUID_LH is a union of `Value: u64` and `Info` (also 8 bytes), so reading
        // `Value` is always valid regardless of how the OS populated the union.
        let luid_value = unsafe { luid.Value };
        Ok(self.luid(luid_value))
    }

    /// Creates a condition that matches the given raw interface LUID.
    pub fn luid(self, luid: u64) -> InterfaceConditionBuilder<InterfaceConditionBuilderHasValue> {
        InterfaceConditionBuilder {
            builder: self.builder.match_type(MatchType::Equal).value_u64(luid),
            _pd: std::marker::PhantomData,
        }
    }
}

impl InterfaceConditionBuilder<InterfaceConditionBuilderHasValue> {
    /// Builds the condition.
    ///
    /// This method is only available when an interface value has been set with
    /// `alias()` or `luid()`.
    pub fn build(self) -> Condition {
        self.builder.build().expect("condition should be valid")
    }
}

/// Typed builder for IP address (subnet/prefix) conditions.
///
/// This builder produces conditions that match the local or remote IP address
/// of a connection against an IPv4 or IPv6 contiguous prefix, using the
/// [`FWP_V4_ADDR_MASK`] / [`FWP_V6_ADDR_MASK`] WFP value types. A single host
/// match (e.g. a specific DNS server) is expressed as a `/32` or `/128`
/// prefix.
///
/// `subnet_v4` is intended for use on an IPv4 layer such as
/// [`Layer::ConnectV4`](crate::Layer::ConnectV4); `subnet_v6` is intended
/// for an IPv6 layer such as [`Layer::ConnectV6`](crate::Layer::ConnectV6).
///
/// # Example
///
/// Permit outbound IPv4 connections to the `192.168.0.0/16` private range.
/// Conditions on the same field on a single filter are combined with
/// logical OR, so additional `subnet_v4(...)` conditions can be chained
/// onto the same `FilterBuilder` to permit more prefixes.
///
/// ```no_run
/// use std::net::Ipv4Addr;
/// use wfp::{ActionType, FilterBuilder, IpAddressConditionBuilder, Layer};
///
/// let filter = FilterBuilder::default()
///     .name("Permit 192.168.0.0/16")
///     .action(ActionType::Permit)
///     .layer(Layer::ConnectV4)
///     .condition(
///         IpAddressConditionBuilder::remote()
///             .subnet_v4(Ipv4Addr::new(192, 168, 0, 0), 16)
///             .build(),
///     );
/// ```
#[derive(Clone)]
pub struct IpAddressConditionBuilder<Value> {
    builder: ConditionBuilder,
    _pd: std::marker::PhantomData<Value>,
}

/// Type-state marker indicating the IP address value has not been set.
#[doc(hidden)]
pub struct IpAddressConditionBuilderMissingValue;

/// Type-state marker indicating the IP address value has been set.
#[doc(hidden)]
pub struct IpAddressConditionBuilderHasValue;

impl IpAddressConditionBuilder<IpAddressConditionBuilderMissingValue> {
    /// Match against the remote IP address
    /// (`FWPM_CONDITION_IP_REMOTE_ADDRESS`).
    pub fn remote() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::RemoteAddress),
            _pd: std::marker::PhantomData,
        }
    }

    /// Match against the local IP address
    /// (`FWPM_CONDITION_IP_LOCAL_ADDRESS`).
    pub fn local() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::LocalAddress),
            _pd: std::marker::PhantomData,
        }
    }
}

impl<V> IpAddressConditionBuilder<V> {
    /// Match an IPv4 prefix `addr/prefix_len`.
    ///
    /// Use this on an IPv4 layer such as
    /// [`Layer::ConnectV4`](crate::Layer::ConnectV4).
    ///
    /// # Panics
    ///
    /// Panics if `prefix_len > 32`.
    pub fn subnet_v4(
        self,
        addr: Ipv4Addr,
        prefix_len: u8,
    ) -> IpAddressConditionBuilder<IpAddressConditionBuilderHasValue> {
        let mask = v4_prefix_to_mask(prefix_len);
        IpAddressConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::Equal)
                .value_v4_addr_mask(u32::from(addr), mask),
            _pd: std::marker::PhantomData,
        }
    }

    /// Match an IPv6 prefix `addr/prefix_len`.
    ///
    /// Use this on an IPv6 layer such as
    /// [`Layer::ConnectV6`](crate::Layer::ConnectV6).
    ///
    /// # Panics
    ///
    /// Panics if `prefix_len > 128`.
    pub fn subnet_v6(
        self,
        addr: Ipv6Addr,
        prefix_len: u8,
    ) -> IpAddressConditionBuilder<IpAddressConditionBuilderHasValue> {
        assert!(prefix_len <= 128, "IPv6 prefix length must be <= 128");
        IpAddressConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::Equal)
                .value_v6_addr_mask(addr.octets(), prefix_len),
            _pd: std::marker::PhantomData,
        }
    }
}

impl IpAddressConditionBuilder<IpAddressConditionBuilderHasValue> {
    /// Builds the condition.
    ///
    /// This method is only available once a subnet has been set with
    /// [`subnet_v4`](Self::subnet_v4) or [`subnet_v6`](Self::subnet_v6).
    pub fn build(self) -> Condition {
        self.builder.build().expect("condition should be valid")
    }
}

/// Convert an IPv4 prefix length into a contiguous host-byte-order mask.
fn v4_prefix_to_mask(prefix_len: u8) -> u32 {
    assert!(prefix_len <= 32, "IPv4 prefix length must be <= 32");
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

/// Specifies how a condition value should be matched against network traffic.
///
/// These correspond to the [`FWP_MATCH_TYPE`] enumeration values.
///
/// [`FWP_MATCH_TYPE`]: https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_match_type
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchType {
    /// The condition value must exactly match the network data.
    Equal = FWP_MATCH_EQUAL,
    /// The network data must be greater than the condition value.
    Greater = FWP_MATCH_GREATER,
    /// The network data must be less than the condition value.
    Less = FWP_MATCH_LESS,
    /// The network data must be greater than or equal to the condition value.
    GreaterOrEqual = FWP_MATCH_GREATER_OR_EQUAL,
    /// The network data must be less than or equal to the condition value.
    LessOrEqual = FWP_MATCH_LESS_OR_EQUAL,
    /// The network data must fall within a specified range.
    Range = FWP_MATCH_RANGE,
}

/// Represents different types of filter conditions that can be applied to network traffic.
///
/// Each condition type corresponds to a specific field in the network packet or connection
/// that can be inspected and matched against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionField {
    /// Remote IP address of the connection.
    RemoteAddress,
    /// Local IP address of the connection.
    LocalAddress,
    /// Remote port number of the connection.
    RemotePort,
    /// Local port number of the connection.
    LocalPort,
    /// IP protocol (TCP, UDP, etc.).
    Protocol,
    /// ICMP type.
    IcmpType,
    /// ICMP code.
    IcmpCode,
    /// Application ID (executable path).
    ///
    /// The lower-case fully qualified device path of the application.
    /// (For example, "\device\hardiskvolume1\program files\application.exe".)
    AppId,
    /// Local interface LUID for the connection.
    LocalInterface,
}

impl ConditionField {
    /// Returns the Windows GUID identifier for this condition field.
    pub fn guid(&self) -> &GUID {
        match self {
            Self::RemoteAddress => &FWPM_CONDITION_IP_REMOTE_ADDRESS,
            Self::LocalAddress => &FWPM_CONDITION_IP_LOCAL_ADDRESS,
            Self::RemotePort => &FWPM_CONDITION_IP_REMOTE_PORT,
            Self::LocalPort => &FWPM_CONDITION_IP_LOCAL_PORT,
            Self::Protocol => &FWPM_CONDITION_IP_PROTOCOL,
            Self::IcmpType => &FWPM_CONDITION_ICMP_TYPE,
            Self::IcmpCode => &FWPM_CONDITION_ICMP_CODE,
            Self::AppId => &FWPM_CONDITION_ALE_APP_ID,
            Self::LocalInterface => &FWPM_CONDITION_IP_LOCAL_INTERFACE,
        }
    }
}

/// Builder for creating filter conditions.
///
/// Conditions specify criteria that network traffic must match for a filter to apply.
/// This builder provides a flexible way to construct conditions with appropriate
/// data types and match operations.
///
/// For type-safe alternatives, consider using the specialized builders:
/// - [`PortConditionBuilder`] for port-based conditions
/// - [`ProtocolConditionBuilder`] for protocol-based conditions
/// - [`AppIdConditionBuilder`] for application-based conditions
///
/// # Example
///
/// ```ignore
/// // Block traffic to port 80 (untyped approach)
/// let condition = ConditionBuilder::default()
///     .field(ConditionField::RemotePort)
///     .match_type(MatchType::Equal)
///     .value_u16(80)
///     .build()?;
/// ```
#[derive(Default, Clone)]
struct ConditionBuilder {
    field: Option<ConditionField>,
    match_type: Option<MatchType>,
    value: Option<Arc<ConditionValue>>,
}

/// Internal representation of condition values with their associated buffers.
enum ConditionValue {
    UInt64(u64),
    UInt32(u32),
    UInt16(u16),
    UInt8(u8),
    String(Vec<u16>),
    ByteBlob { blob: OwnedByteBlob },
    V4AddrMask(FWP_V4_ADDR_AND_MASK),
    V6AddrMask(FWP_V6_ADDR_AND_MASK),
}

impl ConditionBuilder {
    /// Sets the field that this condition will match against.
    pub fn field(mut self, field: ConditionField) -> Self {
        self.field = Some(field);
        self
    }

    /// Sets how the condition value should be matched.
    pub fn match_type(mut self, match_type: MatchType) -> Self {
        self.match_type = Some(match_type);
        self
    }

    /// Sets a 64-bit unsigned integer value for the condition.
    pub fn value_u64(mut self, value: u64) -> Self {
        self.value = Some(ConditionValue::UInt64(value).into());
        self
    }

    /// Sets a 32-bit unsigned integer value for the condition.
    #[allow(dead_code)]
    pub fn value_u32(mut self, value: u32) -> Self {
        self.value = Some(ConditionValue::UInt32(value).into());
        self
    }

    /// Sets a 16-bit unsigned integer value for the condition.
    pub fn value_u16(mut self, value: u16) -> Self {
        self.value = Some(ConditionValue::UInt16(value).into());
        self
    }

    /// Sets a 8-bit unsigned integer value for the condition.
    pub fn value_u8(mut self, value: u8) -> Self {
        self.value = Some(ConditionValue::UInt8(value).into());
        self
    }

    /// Sets a string value for the condition.
    #[allow(dead_code)]
    pub fn value_string(mut self, value: impl AsRef<OsStr>) -> Self {
        let wide_string = string_to_null_terminated_utf16(value);
        self.value = Some(ConditionValue::String(wide_string).into());
        self
    }

    /// Sets a byte blob value for the condition.
    ///
    /// This is typically used for application IDs and other binary data that
    /// needs to be matched exactly. The data is copied into an internal buffer.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let app_id_data = b"\x01\x02\x03\x04"; // Example binary data
    /// let condition = ConditionBuilder::default()
    ///     .field(ConditionField::AppId)
    ///     .match_type(MatchType::Equal)
    ///     .value_byte_blob(app_id_data)
    ///     .build()?;
    /// ```
    pub fn value_byte_blob(mut self, blob: impl Into<OwnedByteBlob>) -> Self {
        self.value = Some(ConditionValue::ByteBlob { blob: blob.into() }.into());
        self
    }

    /// Sets an IPv4 address-and-mask value for the condition.
    ///
    /// `addr` and `mask` are in host byte order, matching the in-memory layout
    /// of [`FWP_V4_ADDR_AND_MASK`].
    pub fn value_v4_addr_mask(mut self, addr: u32, mask: u32) -> Self {
        self.value = Some(ConditionValue::V4AddrMask(FWP_V4_ADDR_AND_MASK { addr, mask }).into());
        self
    }

    /// Sets an IPv6 address-and-prefix-length value for the condition.
    ///
    /// `addr` is the address in network byte order, matching the in-memory
    /// layout of [`FWP_V6_ADDR_AND_MASK`].
    pub fn value_v6_addr_mask(mut self, addr: [u8; 16], prefix_length: u8) -> Self {
        self.value = Some(
            ConditionValue::V6AddrMask(FWP_V6_ADDR_AND_MASK {
                addr,
                prefixLength: prefix_length,
            })
            .into(),
        );
        self
    }

    /// Builds the condition into the internal representation used by FilterBuilder.
    pub fn build(self) -> Option<Condition> {
        let field = self.field?;
        let match_type = self.match_type?;
        let value = self.value?;

        // SAFETY: This is a C struct
        let mut raw_condition: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };

        raw_condition.fieldKey = *field.guid();
        raw_condition.matchType = match_type as i32;

        match &*value {
            ConditionValue::UInt64(val) => {
                raw_condition.conditionValue.r#type = FWP_UINT64;
                // SAFETY: `val` lives in the Arc heap allocation kept alive by `Condition._value`,
                // so the pointer remains valid for the lifetime of the resulting `Condition`.
                raw_condition.conditionValue.Anonymous.uint64 = val as *const u64 as *mut u64;
            }
            ConditionValue::UInt32(val) => {
                raw_condition.conditionValue.r#type = FWP_UINT32;
                raw_condition.conditionValue.Anonymous.uint32 = *val;
            }
            ConditionValue::UInt16(val) => {
                raw_condition.conditionValue.r#type = FWP_UINT16;
                raw_condition.conditionValue.Anonymous.uint16 = *val;
            }
            ConditionValue::UInt8(val) => {
                raw_condition.conditionValue.r#type = FWP_UINT8;
                raw_condition.conditionValue.Anonymous.uint8 = *val;
            }
            ConditionValue::String(wide_str) => {
                raw_condition.conditionValue.r#type = FWP_UNICODE_STRING_TYPE;
                // SAFETY: The data is never mutated, and is tied to the lifetime of Condition
                raw_condition.conditionValue.Anonymous.unicodeString = wide_str.as_ptr() as *mut _;
            }
            ConditionValue::ByteBlob { blob } => {
                raw_condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                // SAFETY: The data is never mutated, and is tied to the lifetime of Condition
                raw_condition.conditionValue.Anonymous.byteBlob = blob.as_ptr() as _;
            }
            ConditionValue::V4AddrMask(addr_and_mask) => {
                raw_condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
                // SAFETY: The data is never mutated, and is tied to the lifetime of Condition
                // (the Arc<ConditionValue> in `_value` keeps the variant payload alive at a
                // stable address).
                raw_condition.conditionValue.Anonymous.v4AddrMask =
                    addr_and_mask as *const _ as *mut _;
            }
            ConditionValue::V6AddrMask(addr_and_mask) => {
                raw_condition.conditionValue.r#type = FWP_V6_ADDR_MASK;
                // SAFETY: The data is never mutated, and is tied to the lifetime of Condition
                // (the Arc<ConditionValue> in `_value` keeps the variant payload alive at a
                // stable address).
                raw_condition.conditionValue.Anonymous.v6AddrMask =
                    addr_and_mask as *const _ as *mut _;
            }
        }

        Some(Condition {
            raw_condition,
            _value: value,
        })
    }
}

/// Internal representation of a built condition.
///
/// This can be added to a [`FilterBuilder`](crate::FilterBuilder).
#[derive(Clone)]
pub struct Condition {
    raw_condition: FWPM_FILTER_CONDITION0,
    // This keeps underlying pointers and data valid
    _value: Arc<ConditionValue>,
}

impl Condition {
    /// Return the underlying FWPM_FILTER_CONDITION0 structure.
    pub(crate) fn raw_condition(&self) -> &FWPM_FILTER_CONDITION0 {
        &self.raw_condition
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    fn assert_field_key_eq(actual: &GUID, expected: &GUID) {
        assert_eq!(actual.data1, expected.data1);
        assert_eq!(actual.data2, expected.data2);
        assert_eq!(actual.data3, expected.data3);
        assert_eq!(actual.data4, expected.data4);
    }

    #[test]
    fn test_condition_local_interface_luid() {
        let luid: u64 = 0xDEAD_BEEF_1234_5678;
        let condition = InterfaceConditionBuilder::local().luid(luid).build();

        assert_field_key_eq(
            &condition.raw_condition.fieldKey,
            &FWPM_CONDITION_IP_LOCAL_INTERFACE,
        );

        assert_eq!(condition.raw_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.raw_condition.conditionValue.r#type, FWP_UINT64);

        // SAFETY: For FWP_UINT64 the `uint64` field is a pointer to the backing u64,
        // kept alive by the Arc inside `Condition`.
        let ptr = unsafe { condition.raw_condition.conditionValue.Anonymous.uint64 };
        assert!(!ptr.is_null());
        assert_eq!(unsafe { *ptr }, luid);
    }

    #[test]
    fn test_condition_local_interface_pointer_stable_after_clone() {
        let luid: u64 = 0xCAFE_BABE_DEAD_F00D;
        let original = InterfaceConditionBuilder::local().luid(luid).build();
        let cloned = original.clone();

        // SAFETY: Same invariant as above - Arc keeps the storage alive.
        let original_value = unsafe { *original.raw_condition.conditionValue.Anonymous.uint64 };
        let cloned_value = unsafe { *cloned.raw_condition.conditionValue.Anonymous.uint64 };

        assert_eq!(original_value, luid);
        assert_eq!(cloned_value, luid);
    }

    #[test]
    fn test_condition_port_remote() {
        let condition = PortConditionBuilder::remote().equal(80).build();

        assert_field_key_eq(
            &condition.raw_condition.fieldKey,
            &FWPM_CONDITION_IP_REMOTE_PORT,
        );

        assert_eq!(condition.raw_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(
            unsafe { condition.raw_condition.conditionValue.Anonymous.uint16 },
            80
        );
    }

    #[test]
    fn test_icmp_type_condition_equal() {
        let condition = IcmpConditionBuilder::r#type().equal(135).build();

        assert_field_key_eq(&condition.raw_condition.fieldKey, &FWPM_CONDITION_ICMP_TYPE);

        assert_eq!(condition.raw_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.raw_condition.conditionValue.r#type, FWP_UINT16);
        assert_eq!(
            unsafe { condition.raw_condition.conditionValue.Anonymous.uint16 },
            135
        );
    }

    #[test]
    fn test_icmp_code_condition_equal() {
        let condition = IcmpConditionBuilder::code().equal(0).build();

        assert_field_key_eq(&condition.raw_condition.fieldKey, &FWPM_CONDITION_ICMP_CODE);

        assert_eq!(condition.raw_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.raw_condition.conditionValue.r#type, FWP_UINT16);
        assert_eq!(
            unsafe { condition.raw_condition.conditionValue.Anonymous.uint16 },
            0
        );
    }

    #[test]
    fn test_icmpv6_protocol_condition() {
        let condition = ProtocolConditionBuilder::icmpv6().build();

        assert_field_key_eq(
            &condition.raw_condition.fieldKey,
            &FWPM_CONDITION_IP_PROTOCOL,
        );

        assert_eq!(condition.raw_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.raw_condition.conditionValue.r#type, FWP_UINT8);
        assert_eq!(
            unsafe { condition.raw_condition.conditionValue.Anonymous.uint8 },
            58
        );
    }

    #[test]
    fn test_v4_prefix_to_mask() {
        assert_eq!(v4_prefix_to_mask(0), 0x00000000);
        assert_eq!(v4_prefix_to_mask(8), 0xFF000000);
        assert_eq!(v4_prefix_to_mask(16), 0xFFFF0000);
        assert_eq!(v4_prefix_to_mask(24), 0xFFFFFF00);
        assert_eq!(v4_prefix_to_mask(32), 0xFFFFFFFF);
    }

    #[test]
    #[should_panic(expected = "IPv4 prefix length must be <= 32")]
    fn test_v4_prefix_to_mask_too_large() {
        let _ = v4_prefix_to_mask(33);
    }

    #[test]
    fn test_subnet_v4_remote() {
        let condition = IpAddressConditionBuilder::remote()
            .subnet_v4(Ipv4Addr::new(192, 168, 0, 0), 16)
            .build();

        assert_field_key_eq(
            &condition.raw_condition.fieldKey,
            &FWPM_CONDITION_IP_REMOTE_ADDRESS,
        );
        assert_eq!(condition.raw_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(
            condition.raw_condition.conditionValue.r#type,
            FWP_V4_ADDR_MASK
        );

        let v4 = unsafe { &*condition.raw_condition.conditionValue.Anonymous.v4AddrMask };
        assert_eq!(v4.addr, 0xC0A80000);
        assert_eq!(v4.mask, 0xFFFF0000);
    }

    #[test]
    fn test_subnet_v4_local() {
        let condition = IpAddressConditionBuilder::local()
            .subnet_v4(Ipv4Addr::new(127, 0, 0, 0), 8)
            .build();

        assert_field_key_eq(
            &condition.raw_condition.fieldKey,
            &FWPM_CONDITION_IP_LOCAL_ADDRESS,
        );
        let v4 = unsafe { &*condition.raw_condition.conditionValue.Anonymous.v4AddrMask };
        assert_eq!(v4.addr, 0x7F000000);
        assert_eq!(v4.mask, 0xFF000000);
    }

    #[test]
    fn test_subnet_v6_remote() {
        let condition = IpAddressConditionBuilder::remote()
            .subnet_v6(Ipv6Addr::from_str("fe80::").unwrap(), 10)
            .build();

        assert_field_key_eq(
            &condition.raw_condition.fieldKey,
            &FWPM_CONDITION_IP_REMOTE_ADDRESS,
        );
        assert_eq!(condition.raw_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(
            condition.raw_condition.conditionValue.r#type,
            FWP_V6_ADDR_MASK
        );

        let v6 = unsafe { &*condition.raw_condition.conditionValue.Anonymous.v6AddrMask };
        assert_eq!(v6.addr[0], 0xfe);
        assert_eq!(v6.addr[1], 0x80);
        for byte in &v6.addr[2..] {
            assert_eq!(*byte, 0);
        }
        assert_eq!(v6.prefixLength, 10);
    }

    #[test]
    #[should_panic(expected = "IPv6 prefix length must be <= 128")]
    fn test_subnet_v6_prefix_too_large() {
        let _ = IpAddressConditionBuilder::remote()
            .subnet_v6(Ipv6Addr::UNSPECIFIED, 129)
            .build();
    }
}
