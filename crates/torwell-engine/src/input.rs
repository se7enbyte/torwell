//! Bounded request input.

use std::io::Read;

use torwell_protocol::{ErrorKind, ProtocolError, MAX_MESSAGE_BYTES};

/// Reads at most [`MAX_MESSAGE_BYTES`] bytes. One byte more is read to detect overflow, but
/// never more than that is buffered.
pub fn read_request(reader: impl Read) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    reader
        .take(MAX_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| {
            ProtocolError::new(
                ErrorKind::InvalidRequest,
                format!("cannot read request: {e}"),
            )
        })?;
    if buf.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::new(
            ErrorKind::MessageTooLarge,
            format!("request exceeds {MAX_MESSAGE_BYTES} bytes"),
        ));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_the_limit_is_accepted_and_one_more_is_refused() {
        assert_eq!(
            read_request(&vec![b' '; MAX_MESSAGE_BYTES][..])
                .unwrap()
                .len(),
            MAX_MESSAGE_BYTES
        );
        let err = read_request(&vec![b' '; MAX_MESSAGE_BYTES + 1][..]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::MessageTooLarge);
    }

    #[test]
    fn endless_input_is_cut_off() {
        let err = read_request(std::io::repeat(b'x')).unwrap_err();
        assert_eq!(err.kind, ErrorKind::MessageTooLarge);
    }
}
