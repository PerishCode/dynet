use std::net::SocketAddr;

use crate::{RuntimeCounters, RuntimeEvent, RuntimeEventKind};

pub(crate) struct SessionEventContext {
    flow_id: String,
    transport: &'static str,
    session: usize,
    target: SocketAddr,
    client: SocketAddr,
}

impl SessionEventContext {
    pub(crate) fn tcp(session: usize, target: SocketAddr, client: SocketAddr) -> Self {
        Self::new("tcp", session, target, client)
    }

    pub(crate) fn udp(session: usize, target: SocketAddr, client: SocketAddr) -> Self {
        Self::new("udp", session, target, client)
    }

    fn new(
        transport: &'static str,
        session: usize,
        target: SocketAddr,
        client: SocketAddr,
    ) -> Self {
        Self {
            flow_id: format!("{transport}-session-{session}"),
            transport,
            session,
            target,
            client,
        }
    }
}

pub(crate) fn emit_session_events(
    counters: &RuntimeCounters,
    context: &SessionEventContext,
    events: Vec<RuntimeEvent>,
) -> Result<(), String> {
    let mut current_attempt = None;
    let mut attempts = 0_usize;
    for mut event in events {
        let kind = event.kind;
        if kind == RuntimeEventKind::OutboundAttemptStarted {
            attempts += 1;
            current_attempt = Some(attempts);
        }
        attach_base(&mut event, context);
        if let Some(attempt) = current_attempt {
            attach_attempt(&mut event, context, attempt);
        }
        if matches!(
            kind,
            RuntimeEventKind::DialerCascadeAttemptStarted
                | RuntimeEventKind::DialerCascadeAttemptFinished
        ) {
            attach_cascade_attempt(&mut event, context);
        }
        counters.emit(event)?;
        if kind == RuntimeEventKind::OutboundAttemptFinished {
            current_attempt = None;
        }
    }
    Ok(())
}

fn attach_base(event: &mut RuntimeEvent, context: &SessionEventContext) {
    field_if_missing(event, "flowId", &context.flow_id);
    field_if_missing(event, "sessionTransport", context.transport);
    field_if_missing(event, "session", context.session);
    field_if_missing(event, "target", context.target);
    field_if_missing(event, "client", context.client);
}

fn attach_attempt(event: &mut RuntimeEvent, context: &SessionEventContext, attempt: usize) {
    field_if_missing(event, "attempt", attempt);
    field_if_missing(
        event,
        "attemptId",
        format!("{}-attempt-{attempt}", context.flow_id),
    );
}

fn attach_cascade_attempt(event: &mut RuntimeEvent, context: &SessionEventContext) {
    let Some(attempt) = event.fields.get("attempt").cloned() else {
        return;
    };
    field_if_missing(
        event,
        "cascadeAttemptId",
        format!("{}-cascade-{attempt}", context.flow_id),
    );
}

fn field_if_missing(event: &mut RuntimeEvent, key: &str, value: impl ToString) {
    event
        .fields
        .entry(key.to_string())
        .or_insert_with(|| value.to_string());
}
