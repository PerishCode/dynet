use dynet_runtime::dns_reverse_from_wire;

#[test]
fn extracts_real_a_answer() {
    let reverse = dns_reverse_from_wire(&dns_query(), &dns_response(), 100).unwrap();

    assert_eq!(reverse.records.len(), 1);
    assert_eq!(reverse.records[0].query, "www.google.com");
    assert_eq!(reverse.records[0].address.to_string(), "142.250.72.4");
    assert_eq!(reverse.records[0].ttl_secs, 60);
}

fn dns_query() -> Vec<u8> {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    packet.extend_from_slice(&[
        3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1,
        0, 1,
    ]);
    packet
}

fn dns_response() -> Vec<u8> {
    let mut packet = dns_query();
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet[6] = 0x00;
    packet[7] = 0x01;
    packet.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 142, 250, 72, 4,
    ]);
    packet
}
