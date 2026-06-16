use crate::Error;

const WINDOW_BITS: u64 = 64;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(super) struct ReplayWindow {
    latest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    pub(super) fn check_and_update(&mut self, packet_id: u64) -> Result<(), Error> {
        let Some(latest) = self.latest else {
            self.latest = Some(packet_id);
            self.seen = 1;
            return Ok(());
        };

        if packet_id > latest {
            let shift = packet_id - latest;
            self.seen = if shift >= WINDOW_BITS {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.latest = Some(packet_id);
            return Ok(());
        }

        let behind = latest - packet_id;
        if behind >= WINDOW_BITS {
            return Err(replay_error("packet ID is outside the replay window"));
        }
        let bit = 1_u64 << behind;
        if self.seen & bit != 0 {
            return Err(replay_error("duplicate packet ID"));
        }
        self.seen |= bit;
        Ok(())
    }
}

fn replay_error(message: &str) -> Error {
    Error::new(
        "outbound-crypto",
        format!("Shadowsocks 2022 UDP replay check failed: {message}"),
    )
}
