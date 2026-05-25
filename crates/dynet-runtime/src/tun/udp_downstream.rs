use std::sync::atomic::Ordering;

use smoltcp::socket::udp;

use crate::{
    resolver::trace::classify_runtime_error, RuntimeCounters, RuntimeEvent, RuntimeEventKind,
};

use super::{tcp, udp_forward::Session, udp_packet};

const BUFFER_BYTES: usize = 2048;

pub(crate) fn drain(
    tun_socket: &mut udp::Socket<'_>,
    session: &mut Session,
    counters: &RuntimeCounters,
) -> Result<(), String> {
    loop {
        let mut response = [0_u8; BUFFER_BYTES];
        match session.socket.recv(&mut response) {
            Ok(size) => match udp_packet::send_response(
                tun_socket,
                session.client,
                session.target,
                &response[..size],
            ) {
                Ok(sent) => emit_received(session, counters, sent)?,
                Err(error) => {
                    counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
                    counters.emit(
                        RuntimeEvent::new(RuntimeEventKind::UdpSessionFailed)
                            .field("session", session.id)
                            .field("flowId", format!("udp-session-{}", session.id))
                            .field("target", session.target)
                            .field("client", session.client)
                            .field("outbound", &session.outbound)
                            .field("errorType", classify_runtime_error(&error))
                            .field("error", error),
                    )?;
                    return Ok(());
                }
            },
            Err(error) if tcp::transient_read_error(&error) => return Ok(()),
            Err(error) => {
                counters.udp_session_failures.fetch_add(1, Ordering::SeqCst);
                counters.udp_dropped_packets.fetch_add(1, Ordering::SeqCst);
                counters.emit(
                    RuntimeEvent::new(RuntimeEventKind::UdpSessionFailed)
                        .field("session", session.id)
                        .field("flowId", format!("udp-session-{}", session.id))
                        .field("target", session.target)
                        .field("client", session.client)
                        .field("outbound", &session.outbound)
                        .field("errorType", classify_runtime_error(&error.to_string()))
                        .field(
                            "error",
                            format!("failed to read proxied UDP payload: {error}"),
                        ),
                )?;
                return Ok(());
            }
        }
    }
}

fn emit_received(
    session: &mut Session,
    counters: &RuntimeCounters,
    bytes: usize,
) -> Result<(), String> {
    session.downstream_bytes += bytes;
    session.last_activity = std::time::Instant::now();
    counters
        .udp_downstream_bytes
        .fetch_add(bytes, Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::UdpSessionPayloadReceived)
            .field("session", session.id)
            .field("flowId", format!("udp-session-{}", session.id))
            .field("target", session.target)
            .field("client", session.client)
            .field("outbound", &session.outbound)
            .field("bytes", bytes),
    )
}
