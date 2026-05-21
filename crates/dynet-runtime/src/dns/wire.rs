use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dynet_core::DnsReverseIndex;

pub fn dns_reverse_from_wire(
    query: &[u8],
    response: &[u8],
    observed_at_secs: u64,
) -> Result<DnsReverseIndex, String> {
    let query_name = query_name_from_wire(query)?;
    let records = parse_answer_records(response)?;
    let canonical = records.iter().find_map(|record| match record {
        AnswerRecord::Cname { target, .. } => Some(target.clone()),
        _ => None,
    });
    let mut reverse = DnsReverseIndex {
        now_secs: Some(observed_at_secs),
        ..Default::default()
    };
    for record in &records {
        if let AnswerRecord::Address {
            name,
            address,
            ttl_secs,
        } = record
        {
            let canonical = canonical.as_deref().or_else(|| {
                if name != &query_name {
                    Some(name.as_str())
                } else {
                    None
                }
            });
            reverse.insert_real_answer(
                &query_name,
                canonical,
                *address,
                observed_at_secs,
                *ttl_secs,
            );
        }
    }
    Ok(reverse)
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum AnswerRecord {
    Address {
        name: String,
        address: IpAddr,
        ttl_secs: u32,
    },
    Cname {
        name: String,
        target: String,
    },
}

pub(crate) fn query_name_from_wire(packet: &[u8]) -> Result<String, String> {
    if packet.len() < 12 {
        return Err("DNS query is shorter than header".to_string());
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    if questions == 0 {
        return Err("DNS query has no question".to_string());
    }
    parse_name(packet, 12).map(|(name, _)| name)
}

fn parse_answer_records(packet: &[u8]) -> Result<Vec<AnswerRecord>, String> {
    if packet.len() < 12 {
        return Err("DNS response is shorter than header".to_string());
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    let mut offset = 12;
    for _ in 0..questions {
        let (_, next) = parse_name(packet, offset)?;
        offset = checked_advance(packet, next, 4)?;
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        let (name, next) = parse_name(packet, offset)?;
        offset = next;
        let header_end = checked_advance(packet, offset, 10)?;
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let ttl_secs = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let data_len = usize::from(u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]));
        let data_end = checked_advance(packet, header_end, data_len)?;
        match (record_type, data_len) {
            (1, 4) => records.push(AnswerRecord::Address {
                name,
                address: IpAddr::V4(Ipv4Addr::new(
                    packet[header_end],
                    packet[header_end + 1],
                    packet[header_end + 2],
                    packet[header_end + 3],
                )),
                ttl_secs,
            }),
            (28, 16) => {
                let bytes: [u8; 16] = packet[header_end..data_end]
                    .try_into()
                    .map_err(|_| "invalid AAAA record length".to_string())?;
                records.push(AnswerRecord::Address {
                    name,
                    address: IpAddr::V6(Ipv6Addr::from(bytes)),
                    ttl_secs,
                });
            }
            (5, _) => {
                let (target, _) = parse_name(packet, header_end)?;
                records.push(AnswerRecord::Cname { name, target });
            }
            _ => {}
        }
        offset = data_end;
    }
    Ok(records)
}

fn parse_name(packet: &[u8], offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut consumed = None;
    let mut jumps = 0;
    loop {
        if cursor >= packet.len() {
            return Err("DNS name exceeds packet length".to_string());
        }
        let len = packet[cursor];
        if len & 0xc0 == 0xc0 {
            let next = checked_advance(packet, cursor, 2)?;
            let pointer = usize::from(u16::from_be_bytes([
                packet[cursor] & 0x3f,
                packet[cursor + 1],
            ]));
            consumed.get_or_insert(next);
            cursor = pointer;
            jumps += 1;
            if jumps > 16 {
                return Err("DNS name compression loop detected".to_string());
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return Err("DNS name uses unsupported label format".to_string());
        }
        cursor += 1;
        if len == 0 {
            let next = consumed.unwrap_or(cursor);
            return Ok((labels.join("."), next));
        }
        let label_len = usize::from(len);
        let next = checked_advance(packet, cursor, label_len)?;
        let label = String::from_utf8_lossy(&packet[cursor..next]).into_owned();
        labels.push(label.to_ascii_lowercase());
        cursor = next;
    }
}

fn checked_advance(packet: &[u8], offset: usize, len: usize) -> Result<usize, String> {
    let next = offset
        .checked_add(len)
        .ok_or_else(|| "DNS packet offset overflow".to_string())?;
    if next > packet.len() {
        Err("DNS packet section exceeds packet length".to_string())
    } else {
        Ok(next)
    }
}
