use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DnsQueryInfo {
    pub(crate) transaction_id: u16,
    pub(crate) query_name: String,
    pub(crate) query_type: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DnsResponseInfo {
    pub(crate) transaction_id: u16,
    pub(crate) query_name: Option<String>,
    pub(crate) query_type: Option<String>,
    pub(crate) answer_ips: Vec<String>,
}

pub(crate) fn sniff_query(packet: &[u8]) -> Option<DnsQueryInfo> {
    let transaction_id = transaction_id(packet)?;
    let qdcount = u16_at(packet, 4)?;
    if qdcount == 0 {
        return None;
    }
    let (query_name, offset) = read_name(packet, 12)?;
    let query_type = qtype_label(u16_at(packet, offset)?);
    Some(DnsQueryInfo {
        transaction_id,
        query_name,
        query_type,
    })
}

pub(crate) fn sniff_response(packet: &[u8]) -> Option<DnsResponseInfo> {
    let transaction_id = transaction_id(packet)?;
    let qdcount = u16_at(packet, 4)?;
    let ancount = u16_at(packet, 6)?;
    let mut offset = 12;
    let mut query_name = None;
    let mut query_type = None;

    for index in 0..qdcount {
        let (name, next) = read_name(packet, offset)?;
        offset = next;
        let qtype = u16_at(packet, offset)?;
        offset = offset.checked_add(4)?;
        if index == 0 {
            query_name = Some(name);
            query_type = Some(qtype_label(qtype));
        }
    }

    let mut answer_ips = Vec::new();
    for _ in 0..ancount {
        let (_, next) = read_name(packet, offset)?;
        offset = next;
        let answer_type = u16_at(packet, offset)?;
        let data_len = usize::from(u16_at(packet, offset.checked_add(8)?)?);
        offset = offset.checked_add(10)?;
        let data_end = offset.checked_add(data_len)?;
        let data = packet.get(offset..data_end)?;
        match (answer_type, data) {
            (1, [a, b, c, d]) => answer_ips.push(Ipv4Addr::new(*a, *b, *c, *d).to_string()),
            (28, bytes) if bytes.len() == 16 => {
                let octets: [u8; 16] = bytes.try_into().ok()?;
                answer_ips.push(Ipv6Addr::from(octets).to_string());
            }
            _ => {}
        }
        offset = data_end;
    }

    Some(DnsResponseInfo {
        transaction_id,
        query_name,
        query_type,
        answer_ips,
    })
}

fn transaction_id(packet: &[u8]) -> Option<u16> {
    u16_at(packet, 0)
}

fn u16_at(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn read_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut next_offset = None;
    let mut jumps = 0_u8;

    loop {
        let length = *packet.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(cursor.checked_add(1)?)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, next]));
            next_offset.get_or_insert(cursor.checked_add(2)?);
            cursor = pointer;
            jumps = jumps.checked_add(1)?;
            if jumps > 8 {
                return None;
            }
            continue;
        }
        if length == 0 {
            let end = next_offset.unwrap_or(cursor.checked_add(1)?);
            return Some((labels.join("."), end));
        }
        let label_start = cursor.checked_add(1)?;
        let label_end = label_start.checked_add(usize::from(length))?;
        let label = packet.get(label_start..label_end)?;
        labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
        cursor = label_end;
    }
}

fn qtype_label(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        28 => "AAAA".to_string(),
        5 => "CNAME".to_string(),
        65 => "HTTPS".to_string(),
        other => other.to_string(),
    }
}
