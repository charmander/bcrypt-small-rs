use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

use super::Base64Error;

fn encode(from: &[u8]) -> Box<[u8]> {
	let encoded_size = (from.len() * 4 + 2) / 3;
	let mut result = vec![0_u8; encoded_size];
	super::encode(from, &mut result);
	result.into_boxed_slice()
}

fn decode(from: &[u8]) -> Result<Box<[u8]>, super::Base64Error> {
	let decoded_size = from.len() * 3 / 4;
	let mut result = vec![0_u8; decoded_size];
	super::decode(from, &mut result)?;
	Ok(result.into_boxed_slice())
}

#[test]
fn empty() {
	assert_eq!(decode(&[]).as_ref().map(|b| b.as_ref()), Ok(&[][..]));
	assert_eq!(encode(&[]).as_ref(), &[]);
}

#[test]
fn round_trip() {
	for length in 1..8 {
		for i in 0..2048 {
			let mut s = DefaultHasher::new();
			s.write_usize(length);
			s.write_u32(i);
			let source_bytes = s.finish().to_ne_bytes();
			let bytes = &source_bytes[..length];

			let encoded = encode(bytes);
			let decoded = decode(&encoded);

			assert_eq!(decoded.as_ref().map(|b| b.as_ref()), Ok(bytes));
		}
	}
}

#[test]
fn invalid_characters() {
	assert_eq!(decode(b"a?cd"), Err(Base64Error::InvalidCharacter));
}

#[test]
fn invalid_lengths() {
	assert_eq!(decode(b"a"), Err(Base64Error::Length));
	assert_eq!(decode(b"abcde"), Err(Base64Error::Length));
}
