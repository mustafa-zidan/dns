//! EDNS(0) padding (RFC 7830) for messages sent over encrypted transports,
//! so their length does not give away which name is being looked up.

use anyhow::Result;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};

/// EDNS(0) padding option code.
const EDNS_PADDING: u16 = 12;

/// Block size RFC 8467 recommends for clients padding queries.
pub const QUERY_BLOCK: usize = 128;
/// Block size RFC 8467 recommends for servers padding responses.
pub const RESPONSE_BLOCK: usize = 468;

/// Serializes `message`, padded to a multiple of `block` bytes when it
/// carries EDNS. A message without EDNS cannot carry padding and is sent as is.
pub fn encode_padded(message: &Message, block: usize) -> Result<Vec<u8>> {
    let mut message = message.clone();
    let unpadded = message.to_vec()?.len();
    let Some(edns) = message.edns.as_mut() else {
        return Ok(message.to_vec()?);
    };
    // The option itself adds 4 bytes (code + length) before its payload.
    let padding = (block - (unpadded + 4) % block) % block;
    edns.options_mut()
        .insert(EdnsOption::Unknown(EDNS_PADDING, vec![0; padding]));
    Ok(message.to_vec()?)
}

/// Whether a query asked for padding by padding itself (RFC 8467, section 4.1:
/// servers pad responses only to clients that pad their queries).
pub fn requested(query: &Message) -> bool {
    query
        .edns
        .as_ref()
        .is_some_and(|edns| edns.option(EdnsCode::from(EDNS_PADDING)).is_some())
}
