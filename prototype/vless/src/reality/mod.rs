// Adapted from shoes' MIT-licensed REALITY implementation. This module keeps
// only the client-side protocol kernel needed by dynet's VLESS prototype.
#![allow(
    dead_code,
    clippy::needless_borrows_for_generic_args,
    clippy::needless_range_loop,
    clippy::vec_init_then_push
)]

mod common;
mod reality_aead;
mod reality_auth;
mod reality_certificate;
mod reality_cipher_suite;
mod reality_client_connection;
mod reality_client_verify;
mod reality_io_state;
mod reality_reader_writer;
mod reality_records;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;

pub use reality_client_connection::{
    feed_reality_client_connection, RealityClientConfig, RealityClientConnection,
};
pub(crate) use reality_reader_writer::{RealityReader, RealityWriter};
pub use reality_util::{decode_public_key, decode_short_id};
