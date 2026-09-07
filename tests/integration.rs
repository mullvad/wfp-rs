//! Integration tests for the Windows Filtering Platform library.

use std::ffi::{OsStr, OsString};
use std::net::{Ipv4Addr, Ipv6Addr};

// Import the library modules we want to test
use wfp::*;

// These tests run concurrently (the default test harness) against the same real, global WFP
// engine. Each test therefore uses a unique sublayer weight: BFE breaks ties between
// same-weight sublayers by bumping the weight reported for one of them, which would otherwise
// make `sublayer.weight()` assertions intermittently fail depending on scheduling.

/// `GUID` does not implement `PartialEq`.
fn guid_eq(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_add_filters_and_sublayer() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    // Create a test sublayer
    let test_guid = GUID::from_u128(0x12345678_1234_5678_9abc_def012345678);

    SubLayerBuilder::default()
        .name("Test Sublayer")
        .description("Test sublayer for integration tests")
        .weight(100)
        .guid(test_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    // Create multiple filters in the same transaction
    let http_condition = PortConditionBuilder::remote().equal(80).build();
    let https_condition = PortConditionBuilder::remote().equal(443).build();
    let tcp_condition = ProtocolConditionBuilder::tcp().build();

    // HTTP block filter
    FilterBuilder::default()
        .name("HTTP Block Filter")
        .description("Blocks HTTP traffic")
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .condition(http_condition)
        .condition(tcp_condition.clone())
        .sublayer(test_guid)
        .add(&transaction)
        .expect("Should be able to add HTTP filter");

    // HTTPS permit filter
    FilterBuilder::default()
        .name("HTTPS Permit Filter")
        .description("Permits HTTPS traffic")
        .action(ActionType::Permit)
        .layer(Layer::ConnectV4)
        .condition(https_condition)
        .condition(tcp_condition)
        .sublayer(test_guid)
        .weight(FilterWeight::Exact(12345))
        .add(&transaction)
        .expect("Should be able to add HTTPS filter");

    transaction
        .commit()
        .expect("Should be able to commit multiple filters");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_enumerate_sublayers() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let test_provider_guid = GUID::from_u128(0x0e0e0e0e_1111_2222_3333_444455556666);
    let test_guid = GUID::from_u128(0x0e0e0e0e_1234_5678_9abc_def012345678);

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    ProviderBuilder::default()
        .name("Test Enumeration Provider")
        .description("Provider for sublayer enumeration tests")
        .guid(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add provider");

    SubLayerBuilder::default()
        .name("Test Enumeration Sublayer")
        .description("Test sublayer for enumeration integration tests")
        .weight(101)
        .guid(test_guid)
        .provider(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    transaction
        .commit()
        .expect("Should be able to commit sublayer transaction");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let mut sublayer_enum =
        SubLayerEnumerator::new(&transaction).expect("Should be able to enumerate sublayers");

    let mut found = false;

    while let Some(sublayer) = sublayer_enum.next() {
        let sublayer = sublayer.expect("Should be able to read sublayer");
        if !guid_eq(&sublayer.guid(), &test_guid) {
            continue;
        }

        assert_eq!(
            sublayer.name().as_deref(),
            Some(OsStr::new("Test Enumeration Sublayer"))
        );
        assert_eq!(
            sublayer.description().as_deref(),
            Some(OsStr::new(
                "Test sublayer for enumeration integration tests"
            ))
        );
        assert_eq!(sublayer.weight(), 101);
        assert!(
            sublayer
                .provider()
                .is_some_and(|guid| guid_eq(&guid, &test_provider_guid)),
            "The sublayer should be attached to the test provider"
        );
        assert!(
            !sublayer.persistent(),
            "The sublayer was added to a dynamic session"
        );

        found = true;
        break;
    }

    assert!(found, "Should find the sublayer that was just added");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_enumerate_filters() {
    /// More than the batch size used internally by the enumerator, so that enumeration has to
    /// fetch several batches.
    const NUM_FILTERS: u64 = 120;

    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let test_provider_guid = GUID::from_u128(0x0f0f0f0f_1111_2222_3333_444455556666);
    let test_sublayer_guid = GUID::from_u128(0x0f0f0f0f_1234_5678_9abc_def012345678);

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    ProviderBuilder::default()
        .name("Test Filter Enumeration Provider")
        .description("Provider for filter enumeration tests")
        .guid(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add provider");

    SubLayerBuilder::default()
        .name("Test Filter Enumeration Sublayer")
        .description("Sublayer for filter enumeration tests")
        .weight(102)
        .guid(test_sublayer_guid)
        .provider(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    for i in 0..NUM_FILTERS {
        FilterBuilder::default()
            .name(format!("Test Enumeration Filter {i}"))
            .description("Filter for enumeration integration tests")
            .action(ActionType::Block)
            .layer(Layer::ConnectV4)
            .condition(
                PortConditionBuilder::remote()
                    .equal(1024 + i as u16)
                    .build(),
            )
            .sublayer(test_sublayer_guid)
            .provider(test_provider_guid)
            .add(&transaction)
            .expect("Should be able to add filter");
    }

    transaction
        .commit()
        .expect("Should be able to commit filter transaction");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let mut filter_enum =
        FilterEnumerator::new(&transaction).expect("Should be able to enumerate filters");

    let mut found_names = vec![];
    let mut ids = vec![];

    while let Some(filter) = filter_enum.next() {
        let filter = filter.expect("Should be able to read filter");

        // Filters added by other providers are expected; only look at our own
        if !filter
            .provider()
            .is_some_and(|guid| guid_eq(&guid, &test_provider_guid))
        {
            continue;
        }

        assert_eq!(
            filter.description().as_deref(),
            Some(OsStr::new("Filter for enumeration integration tests"))
        );

        ids.push(filter.id());
        found_names.push(filter.name().expect("The filter should have a name"));
    }

    // All of the filters we added must be enumerated, which requires several batches
    found_names.sort();
    let mut expected_names: Vec<_> = (0..NUM_FILTERS)
        .map(|i| OsString::from(format!("Test Enumeration Filter {i}")))
        .collect();
    expected_names.sort();
    assert_eq!(found_names, expected_names);

    // Filter IDs are assigned by WFP and must be unique
    ids.sort_unstable();
    let num_ids = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), num_ids, "Filter IDs should be unique");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_add_provider_and_attach_filters() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let test_provider_guid = GUID::from_u128(0xdeadbeef_1111_2222_3333_444455556666);
    let test_sublayer_guid = GUID::from_u128(0xdeadbeef_aaaa_bbbb_cccc_ddddeeeeffff);
    let test_filter_guid = GUID::from_u128(0xdeadbeef_1234_5678_9abc_def012345678);

    ProviderBuilder::default()
        .name("Test Provider")
        .description("Provider for integration tests")
        .guid(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add provider");

    SubLayerBuilder::default()
        .name("Test Provider Sublayer")
        .description("Sublayer attached to test provider")
        .weight(103)
        .guid(test_sublayer_guid)
        .provider(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    FilterBuilder::default()
        .name("Test Provider Filter")
        .description("Filter attached to test provider")
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .sublayer(test_sublayer_guid)
        .provider(test_provider_guid)
        .guid(test_filter_guid)
        .add(&transaction)
        .expect("Should be able to add filter");

    transaction
        .commit()
        .expect("Should be able to commit provider transaction");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_app_id_condition() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let test_guid = GUID::from_u128(0xaabbccdd_1234_5678_9abc_def012345678);

    SubLayerBuilder::default()
        .name("Test AppId Sublayer")
        .description("Test sublayer for app ID integration tests")
        .weight(104)
        .guid(test_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    // get_app_id_from_filename returns Err for non-existent paths
    let bad_result = AppIdConditionBuilder::default().equal(r"C:\nonexistent\fake.exe");
    assert!(
        bad_result.is_err(),
        "Should return Err for a nonexistent executable path"
    );

    // get_app_id_from_filename returns Ok for a real executable
    let app_condition = AppIdConditionBuilder::default()
        .equal(r"C:\Windows\System32\ping.exe")
        .expect("Should be able to get app ID from ping.exe");

    FilterBuilder::default()
        .name("Ping Block Filter")
        .description("Blocks ping.exe outbound traffic")
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .condition(app_condition.build())
        .sublayer(test_guid)
        .weight(WeightRange::try_from(15).unwrap())
        .add(&transaction)
        .expect("Should be able to add app ID filter");

    transaction
        .commit()
        .expect("Should be able to commit app ID filter transaction");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_ndp_filter() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let test_guid = GUID::from_u128(0xfeed1234_5678_9abc_def0_123456789abc);

    SubLayerBuilder::default()
        .name("Test NDP Sublayer")
        .description("Test sublayer for NDP integration test")
        .weight(105)
        .guid(test_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    // ICMPv6 NDP messages.
    //
    // Outbound: Router Solicitation (133), Neighbor Solicitation (135),
    //           Neighbor Advertisement (136).
    // Inbound:  Router Advertisement (134), Neighbor Solicitation (135),
    //           Neighbor Advertisement (136), Redirect (137).
    let outbound_types = [133u8, 135, 136];
    let inbound_types = [134u8, 135, 136, 137];

    for t in outbound_types {
        FilterBuilder::default()
            .name("NDP (outbound)")
            .description("Permits outbound ICMPv6 NDP traffic")
            .action(ActionType::Permit)
            .layer(Layer::ConnectV6)
            .condition(ProtocolConditionBuilder::icmpv6().build())
            .condition(IcmpConditionBuilder::r#type().equal(t).build())
            .condition(IcmpConditionBuilder::code().equal(0).build())
            .sublayer(test_guid)
            .add(&transaction)
            .expect("Should be able to add outbound NDP filter");
    }

    for t in inbound_types {
        FilterBuilder::default()
            .name("NDP (inbound)")
            .description("Permits inbound ICMPv6 NDP traffic")
            .action(ActionType::Permit)
            .layer(Layer::AcceptV6)
            .condition(ProtocolConditionBuilder::icmpv6().build())
            .condition(IcmpConditionBuilder::r#type().equal(t).build())
            .condition(IcmpConditionBuilder::code().equal(0).build())
            .sublayer(test_guid)
            .add(&transaction)
            .expect("Should be able to add inbound NDP filter");
    }

    transaction
        .commit()
        .expect("Should be able to commit NDP filter transaction");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_local_interface_condition() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let test_guid = GUID::from_u128(0xbbccddee_2345_6789_abcd_ef0123456789);

    SubLayerBuilder::default()
        .name("Test Interface Sublayer")
        .description("Test sublayer for interface condition integration tests")
        .weight(106)
        .guid(test_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    // ConvertInterfaceAliasToLuid returns an error for an unknown interface.
    let bad_result = InterfaceConditionBuilder::local().alias("definitely-not-an-interface-xyz");
    assert!(
        bad_result.is_err(),
        "Should return Err for a nonexistent interface alias"
    );

    // The loopback pseudo-interface is guaranteed to exist
    let iface_condition = InterfaceConditionBuilder::local()
        .alias("Loopback Pseudo-Interface 1")
        .expect("Should be able to resolve loopback interface alias to a LUID");

    FilterBuilder::default()
        .name("Loopback Permit Filter")
        .description("Permits traffic bound to the loopback interface")
        .action(ActionType::Permit)
        .layer(Layer::ConnectV4)
        .condition(iface_condition.build())
        .sublayer(test_guid)
        .add(&transaction)
        .expect("Should be able to add interface filter");

    transaction
        .commit()
        .expect("Should be able to commit interface filter transaction");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_ip_address_subnet_condition() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let test_guid = GUID::from_u128(0xbbccddee_1234_5678_9abc_def012345678);

    SubLayerBuilder::default()
        .name("Test IP Address Sublayer")
        .description("Test sublayer for IP-prefix integration tests")
        .weight(107)
        .guid(test_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    FilterBuilder::default()
        .name("Permit 192.168.0.0/16")
        .description("Permits the 192.168/16 range")
        .action(ActionType::Permit)
        .layer(Layer::ConnectV4)
        .condition(
            IpAddressConditionBuilder::remote()
                .subnet_v4(Ipv4Addr::new(192, 168, 0, 0), 16)
                .build(),
        )
        .sublayer(test_guid)
        .add(&transaction)
        .expect("Should be able to add v4 LAN filter");

    FilterBuilder::default()
        .name("Permit fe80::/10")
        .description("Permits the IPv6 link-local range")
        .action(ActionType::Permit)
        .layer(Layer::ConnectV6)
        .condition(
            IpAddressConditionBuilder::remote()
                .subnet_v6("fe80::".parse::<Ipv6Addr>().unwrap(), 10)
                .build(),
        )
        .sublayer(test_guid)
        .add(&transaction)
        .expect("Should be able to add v6 link-local filter");

    transaction
        .commit()
        .expect("Should be able to commit IP-address filter transaction");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_filter_metadata_round_trip() {
    const EXACT_WEIGHT: u64 = 0x0123_4567_89ab_cdef;
    const RANGE_WEIGHT: u8 = 5;

    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let test_provider_guid = GUID::from_u128(0x0a0a0a0a_1111_2222_3333_444455556666);
    let test_sublayer_guid = GUID::from_u128(0x0a0a0a0a_1234_5678_9abc_def012345678);

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    ProviderBuilder::default()
        .name("Test Metadata Provider")
        .description("Provider for filter metadata round-trip tests")
        .guid(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add provider");

    SubLayerBuilder::default()
        .name("Test Metadata Sublayer")
        .description("Sublayer for filter metadata round-trip tests")
        .weight(108)
        .guid(test_sublayer_guid)
        .provider(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    // Every filter below is narrowed to an unused high port, so that committing them cannot
    // disturb real traffic on the machine running the tests.

    FilterBuilder::default()
        .name("Exact weight filter")
        .description("Filter with an exact weight")
        .action(ActionType::Permit)
        .layer(Layer::ConnectV6)
        .sublayer(test_sublayer_guid)
        .provider(test_provider_guid)
        .weight(FilterWeight::Exact(EXACT_WEIGHT))
        .condition(ProtocolConditionBuilder::tcp().build())
        .condition(PortConditionBuilder::remote().equal(44443).build())
        .add(&transaction)
        .expect("Should be able to add exact weight filter");

    FilterBuilder::default()
        .name("Range weight filter")
        .description("Filter with a range weight")
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .sublayer(test_sublayer_guid)
        .provider(test_provider_guid)
        .weight(WeightRange::try_from(RANGE_WEIGHT).unwrap())
        .condition(PortConditionBuilder::remote().equal(44444).build())
        .add(&transaction)
        .expect("Should be able to add range weight filter");

    FilterBuilder::default()
        .name("Auto weight filter")
        .description("Filter with an automatic weight")
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .sublayer(test_sublayer_guid)
        .provider(test_provider_guid)
        .weight(FilterWeight::Auto)
        .condition(PortConditionBuilder::remote().equal(44445).build())
        .add(&transaction)
        .expect("Should be able to add auto weight filter");

    transaction
        .commit()
        .expect("Should be able to commit metadata filter transaction");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let mut filter_enum =
        FilterEnumerator::new(&transaction).expect("Should be able to enumerate filters");

    let mut found_names = vec![];

    while let Some(filter) = filter_enum.next() {
        let filter = filter.expect("Should be able to read filter");

        // Filters added by other providers are expected; only look at our own
        if !filter
            .provider()
            .is_some_and(|guid| guid_eq(&guid, &test_provider_guid))
        {
            continue;
        }

        assert!(
            guid_eq(&filter.sublayer(), &test_sublayer_guid),
            "The filter should be attached to the test sublayer"
        );

        let name = filter.name().expect("The filter should have a name");
        match name.to_str().expect("The filter name should be Unicode") {
            "Exact weight filter" => {
                assert_eq!(filter.layer(), Some(Layer::ConnectV6));
                assert!(guid_eq(&filter.layer_guid(), Layer::ConnectV6.guid()));
                assert_eq!(filter.action(), FilterAction::Permit);
                assert_eq!(filter.weight(), Some(FilterWeight::Exact(EXACT_WEIGHT)));
                assert_eq!(
                    filter.effective_weight(),
                    Some(EXACT_WEIGHT),
                    "An exact weight is used verbatim as the effective weight"
                );
                assert_eq!(filter.num_conditions(), 2);
            }
            "Range weight filter" => {
                assert_eq!(filter.layer(), Some(Layer::ConnectV4));
                assert!(guid_eq(&filter.layer_guid(), Layer::ConnectV4.guid()));
                assert_eq!(filter.action(), FilterAction::Block);
                assert_eq!(
                    filter.weight(),
                    Some(FilterWeight::Range(
                        WeightRange::try_from(RANGE_WEIGHT).unwrap()
                    ))
                );
                let effective = filter
                    .effective_weight()
                    .expect("An added filter should have an effective weight");
                assert_eq!(
                    effective >> 60,
                    u64::from(RANGE_WEIGHT),
                    "A range weight sets the high-order 4 bits of the effective weight: {effective:#x}"
                );
                assert_eq!(filter.num_conditions(), 1);
            }
            "Auto weight filter" => {
                assert_eq!(filter.layer(), Some(Layer::ConnectV4));
                assert_eq!(filter.action(), FilterAction::Block);
                assert_eq!(filter.weight(), Some(FilterWeight::Auto));
                let effective = filter
                    .effective_weight()
                    .expect("An added filter should have an effective weight");
                assert!(
                    effective < 1 << 60,
                    "BFE generates automatic weights in [0, 2^60): {effective:#x}"
                );
                assert_eq!(filter.num_conditions(), 1);
            }
            other => panic!("Unexpected filter {other:?} under the test provider"),
        }

        found_names.push(name);
    }

    found_names.sort();
    assert_eq!(
        found_names,
        [
            "Auto weight filter",
            "Exact weight filter",
            "Range weight filter",
        ]
        .map(OsString::from)
    );
}

/// Enumeration returns every filter on the system, including filters at layers that [`Layer`] does
/// not name. Those must be reported as an unknown layer rather than being mapped onto a variant.
#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_enumerate_unknown_layers() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let mut filter_enum =
        FilterEnumerator::new(&transaction).expect("Should be able to enumerate filters");

    let mut num_known = 0usize;
    let mut num_unknown = 0usize;

    while let Some(filter) = filter_enum.next() {
        let filter = filter.expect("Should be able to read filter");

        match filter.layer() {
            Some(layer) => {
                assert!(
                    guid_eq(&filter.layer_guid(), layer.guid()),
                    "`layer` and `layer_guid` should agree"
                );
                num_known += 1;
            }
            None => num_unknown += 1,
        }
    }

    // Windows always installs filters of its own, at far more layers than `Layer` names
    assert!(
        num_unknown > 0,
        "Expected some filters at layers outside `Layer` ({num_known} known, {num_unknown} unknown)"
    );
}
