//! Layers

use crate::GUID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

/// Specifies the network layer at which a filter operates.
///
/// Different layers provide different types of network information and
/// allow filtering at various points in the network stack. These correspond
/// to predefined layer GUIDs in the Windows Filtering Platform.
///
/// For more information about filtering layers, see the [WFP Layer Reference].
///
/// [WFP Layer Reference]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// Used for authorizing accept requests for incoming TCP IPv4 connections, as well as incoming
    /// non-TCP traffic based on the first packed received.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`].
    ///
    /// [`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    AcceptV4,
    /// Used for authorizing accept requests for incoming TCP IPv6 connections, as well as incoming
    /// non-TCP traffic based on the first packed received.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`].
    ///
    /// [`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    AcceptV6,
    /// Used for authorizing accept requests for outgoing TCP IPv4 connections, as well as outgoing
    /// non-TCP traffic based on the first packed received.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_AUTH_CONNECT_V4`].
    ///
    /// [`FWPM_LAYER_ALE_AUTH_CONNECT_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    ConnectV4,
    /// Used for authorizing accept requests for outgoing TCP IPv6 connections, as well as outgoing
    /// non-TCP traffic based on the first packed received.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_AUTH_CONNECT_V6`].
    ///
    /// [`FWPM_LAYER_ALE_AUTH_CONNECT_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    ConnectV6,
    /// Filters at this layer can inspect an IPv4 connection that has been authorized.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4`].
    ///
    /// [`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    FlowEstablishedV4,
    /// Filters at this layer can inspect an IPv6 connection that has been authorized.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6`].
    ///
    /// [`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    FlowEstablishedV6,
    /// Incoming IPv4 packets before any IP header processing has occurred.
    ///
    /// Corresponds to [`FWPM_LAYER_INBOUND_IPPACKET_V4`].
    ///
    /// [`FWPM_LAYER_INBOUND_IPPACKET_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    InboundIpPacketV4,
    /// Incoming IPv6 packets before any IP header processing has occurred.
    ///
    /// Corresponds to [`FWPM_LAYER_INBOUND_IPPACKET_V6`].
    ///
    /// [`FWPM_LAYER_INBOUND_IPPACKET_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    InboundIpPacketV6,
    /// Outbound IPv4 packets just before fragmentation.
    ///
    /// Corresponds to [`FWPM_LAYER_OUTBOUND_IPPACKET_V4`].
    ///
    /// [`FWPM_LAYER_OUTBOUND_IPPACKET_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    OutboundIpPacketV4,
    /// Outbound IPv6 packets just before fragmentation.
    ///
    /// Corresponds to [`FWPM_LAYER_OUTBOUND_IPPACKET_V6`].
    ///
    /// [`FWPM_LAYER_OUTBOUND_IPPACKET_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    OutboundIpPacketV6,
    /// Incoming IPv4 packets before transport layer processing.
    ///
    /// Corresponds to [`FWPM_LAYER_INBOUND_TRANSPORT_V4`].
    ///
    /// [`FWPM_LAYER_INBOUND_TRANSPORT_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    InboundTransportV4,
    /// Incoming IPv6 packets before transport layer processing.
    ///
    /// Corresponds to [`FWPM_LAYER_INBOUND_TRANSPORT_V6`].
    ///
    /// [`FWPM_LAYER_INBOUND_TRANSPORT_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    InboundTransportV6,
    /// Outbound IPv4 packets before any network layer processing.
    ///
    /// Corresponds to [`FWPM_LAYER_OUTBOUND_TRANSPORT_V4`].
    ///
    /// [`FWPM_LAYER_OUTBOUND_TRANSPORT_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    OutboundTransportV4,
    /// Outbound IPv6 packets before any network layer processing.
    ///
    /// Corresponds to [`FWPM_LAYER_OUTBOUND_TRANSPORT_V6`].
    ///
    /// [`FWPM_LAYER_OUTBOUND_TRANSPORT_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    OutboundTransportV6,
}

impl Layer {
    /// Returns the Windows GUID identifier for this layer.
    ///
    /// This is used internally when communicating with the Windows Filtering Platform API.
    pub fn guid(&self) -> &GUID {
        match self {
            Self::AcceptV4 => &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            Self::AcceptV6 => &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            Self::ConnectV4 => &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::ConnectV6 => &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            Self::FlowEstablishedV4 => &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            Self::FlowEstablishedV6 => &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
            Self::InboundIpPacketV4 => &FWPM_LAYER_INBOUND_IPPACKET_V4,
            Self::InboundIpPacketV6 => &FWPM_LAYER_INBOUND_IPPACKET_V6,
            Self::OutboundIpPacketV4 => &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
            Self::OutboundIpPacketV6 => &FWPM_LAYER_OUTBOUND_IPPACKET_V6,
            Self::InboundTransportV4 => &FWPM_LAYER_INBOUND_TRANSPORT_V4,
            Self::InboundTransportV6 => &FWPM_LAYER_INBOUND_TRANSPORT_V6,
            Self::OutboundTransportV4 => &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            Self::OutboundTransportV6 => &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        }
    }
}
