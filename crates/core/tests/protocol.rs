use p2p_core::{APP_NAME, CoreError, PROTOCOL_VERSION, app_info, parse_protocol_version};

#[test]
fn rejects_unknown_and_malformed_protocol_strings() {
    assert!(matches!(
        parse_protocol_version("p2p-messenger/2"),
        Err(CoreError::UnsupportedProtocolVersion(2))
    ));
    assert!(matches!(
        parse_protocol_version("other/1"),
        Err(CoreError::InvalidProtocolPrefix { .. })
    ));
    assert!(matches!(
        parse_protocol_version("p2p-messenger/"),
        Err(CoreError::InvalidProtocolNumber)
    ));
    assert!(matches!(
        parse_protocol_version("p2p-messenger/abc"),
        Err(CoreError::InvalidProtocolNumber)
    ));
    assert!(matches!(
        parse_protocol_version("p2p-messenger/999999999999999999999999"),
        Err(CoreError::InvalidProtocolNumber)
    ));
}

#[test]
fn app_info_is_json_serializable() {
    let json = serde_json::to_string(&app_info()).expect("AppInfo must serialize");
    assert!(json.contains(APP_NAME));
    assert!(json.contains(PROTOCOL_VERSION));
}
