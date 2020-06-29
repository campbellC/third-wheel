use httparse::parse_chunk_size;
use httparse::Status;

/// BodyParser simply checks whether the full body is present
/// HTTP 1.1 has bodies possible: empty, chunked or content-length bounded.
/// Gotcha: Chunked uses hex digits to count octets, content-length uses decimal digits
#[derive(Debug)]
pub(super) enum BodyParser {
    Chunked,
    ContentLength(usize),
    Empty,
}

impl BodyParser {
    pub(super) fn is_complete(&self, bytes: &[u8]) -> bool {
        match *self {
            Self::Chunked => {
                let mut current: usize = 0;
                loop {
                    match parse_chunk_size(&bytes[current..]) {
                        Err(_) | Ok(Status::Partial) => return false,
                        Ok(Status::Complete((parsed_up_to, chunk_size))) => {
                            // parsed_up_to is the beginning of the next chunk
                            // chunk size is the number of bytes of content
                            // each chunk should be followed by a CRLF (\r\n) two bytes long
                            // The body is finished by 0\r\n\r\n
                            let chunk_size = chunk_size as usize;
                            if chunk_size == 0 && current + parsed_up_to == bytes.len() - 2 {
                                return true;
                            } else if current + parsed_up_to + chunk_size + 2 >= bytes.len() {
                                return false;
                            } else {
                                current += parsed_up_to + chunk_size + 2;
                            }
                        }
                    };
                }
            }
            Self::ContentLength(expected_length) => bytes.len() == expected_length,
            Self::Empty => true,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn chunked_not_complete() {
        let body_parser = BodyParser::Chunked;

        assert!(!body_parser.is_complete(b"1\r\n"));
        assert!(!body_parser.is_complete(b"1\r\na\r\n"));
        assert!(!body_parser.is_complete(b"1\r\na\r\n0\r\n"));
        assert!(!body_parser.is_complete(b"1\r\na\r\n0\r\n\r"));

        let example = b"4\r\nWiki\r\n5\r\npedia\r\nE\r\nin\r\n\r\nchunks.\r\n0\r\n\r\n";
        for i in 0..42 {
            assert!(!body_parser.is_complete(&example[..i]));
        }
    }

    #[test]
    fn chunked_complete() {
        let body_parser = BodyParser::Chunked;

        let example = b"4\r\nWiki\r\n5\r\npedia\r\nE\r\nin\r\n\r\nchunks.\r\n0\r\n\r\n";
        assert!(body_parser.is_complete(example));
        let example = b"E\r\nin\r\n\r\nchunks.\r\n0\r\n\r\n";
        assert!(body_parser.is_complete(example));
        assert!(body_parser.is_complete(b"1\r\na\r\na\r\nabcdefghij\r\n0\r\n\r\n"))
    }

    #[test]
    fn content_length_complete() {
        assert!(BodyParser::ContentLength(1).is_complete(b"a"));
        assert!(BodyParser::ContentLength(10).is_complete(b"abcdefgh\r\n"));
    }

    #[test]
    fn content_length_not_complete() {
        assert!(!BodyParser::ContentLength(1).is_complete(b""));
        assert!(!BodyParser::ContentLength(10).is_complete(b"abchij\r\n"));
    }
}
