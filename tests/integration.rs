//! Integration tests for the Windows Filtering Platform library.

use std::ffi::{OsStr, OsString};
use std::net::{Ipv4Addr, Ipv6Addr};

// Import the library modules we want to test
use wfp::*;

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
        .weight(100)
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
        assert_eq!(sublayer.weight(), 100);
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
        .weight(100)
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
fn test_enumerate_with_template() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    // The tests run in parallel and share the machine-global WFP object namespace, so these GUIDs
    // must not be used by any other test.
    let test_provider_guid = GUID::from_u128(0x0d0d0d0d_1111_2222_3333_444455556666);
    let test_sublayer_guid = GUID::from_u128(0x0d0d0d0d_1234_5678_9abc_def012345678);

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    ProviderBuilder::default()
        .name("Test Template Enumeration Provider")
        .description("Provider for template enumeration tests")
        .guid(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add provider");

    SubLayerBuilder::default()
        .name("Test Template Enumeration Sublayer")
        .description("Sublayer for template enumeration tests")
        .weight(100)
        .guid(test_sublayer_guid)
        .provider(test_provider_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    for (name, action) in [
        ("Test Template Filter Block 0", ActionType::Block),
        ("Test Template Filter Block 1", ActionType::Block),
        ("Test Template Filter Permit", ActionType::Permit),
    ] {
        FilterBuilder::default()
            .name(name)
            .description("Filter for template enumeration tests")
            .action(action)
            .layer(Layer::ConnectV4)
            .sublayer(test_sublayer_guid)
            .provider(test_provider_guid)
            .add(&transaction)
            .expect("Should be able to add filter");
    }

    transaction
        .commit()
        .expect("Should be able to commit filter transaction");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    // Only the sublayer belonging to the test provider must be enumerated
    let template = SubLayerEnumTemplate::default().provider(test_provider_guid);
    let mut sublayer_enum = SubLayerEnumerator::with_template(&transaction, &template)
        .expect("Should be able to enumerate sublayers");

    let mut sublayer_names = vec![];
    while let Some(sublayer) = sublayer_enum.next() {
        let sublayer = sublayer.expect("Should be able to read sublayer");
        assert!(
            sublayer
                .provider()
                .is_some_and(|guid| guid_eq(&guid, &test_provider_guid)),
            "The template should only return sublayers of the test provider"
        );
        sublayer_names.push(sublayer.name().expect("The sublayer should have a name"));
    }
    assert_eq!(
        sublayer_names,
        vec![OsString::from("Test Template Enumeration Sublayer")]
    );
    drop(sublayer_enum);

    // Only the filters belonging to the test provider must be enumerated. Filters are always
    // enumerated one layer at a time; all of the test filters are at the same layer.
    let template = FilterEnumTemplate::default()
        .layer(Layer::ConnectV4)
        .provider(test_provider_guid);
    let mut filter_enum = FilterEnumerator::with_template(&transaction, &template)
        .expect("Should be able to enumerate filters");

    let mut filter_names = vec![];
    while let Some(filter) = filter_enum.next() {
        let filter = filter.expect("Should be able to read filter");
        assert!(
            filter
                .provider()
                .is_some_and(|guid| guid_eq(&guid, &test_provider_guid)),
            "The template should only return filters of the test provider"
        );
        filter_names.push(filter.name().expect("The filter should have a name"));
    }
    filter_names.sort();
    assert_eq!(
        filter_names,
        vec![
            OsString::from("Test Template Filter Block 0"),
            OsString::from("Test Template Filter Block 1"),
            OsString::from("Test Template Filter Permit"),
        ]
    );
    drop(filter_enum);

    // Restricting the action type must exclude the blocking filters
    let template = FilterEnumTemplate::default()
        .layer(Layer::ConnectV4)
        .provider(test_provider_guid)
        .action(ActionType::Permit);
    let mut filter_enum = FilterEnumerator::with_template(&transaction, &template)
        .expect("Should be able to enumerate filters");

    let mut filter_names = vec![];
    while let Some(filter) = filter_enum.next() {
        let filter = filter.expect("Should be able to read filter");
        filter_names.push(filter.name().expect("The filter should have a name"));
    }
    assert_eq!(
        filter_names,
        vec![OsString::from("Test Template Filter Permit")]
    );
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
        .weight(100)
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
        .weight(100)
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
        .weight(100)
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
        .weight(100)
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
        .weight(100)
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
