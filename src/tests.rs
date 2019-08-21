use std::error::Error;
use std::str;

use super::{CompareError, Hash, HashError, ParseError, WorkFactor, compare, hash};

const WORK_FACTOR: WorkFactor = WorkFactor::EXP4;

#[test]
fn comparisons() -> Result<(), Box<dyn Error>> {
	let h = hash("hello, world!", WORK_FACTOR)?;
	assert_eq!(compare("hello, world!", &h), Ok(true));
	assert_eq!(compare("helln, world!", &h), Ok(false));
	assert_eq!(compare("hello, world", &h), Ok(false));
	assert_eq!(compare("hello, world!!", &h), Ok(false));
	Ok(())
}

#[test]
fn hash_invalid() -> Result<(), Box<dyn Error>> {
	assert_eq!(hash("hell\0, world!", WORK_FACTOR).err(), Some(HashError::ZeroByte));
	assert_eq!(hash(str::from_utf8(&[b'z'; 73])?, WORK_FACTOR).err(), Some(HashError::Length));
	assert_eq!(hash(str::from_utf8(&[0; 73])?, WORK_FACTOR).err(), Some(HashError::Length));
	Ok(())
}

#[test]
fn compare_invalid() -> Result<(), Box<dyn Error>> {
	let h = hash("hello, world!", WORK_FACTOR)?;
	assert_eq!(compare("hell\0, world!", &h), Err(CompareError::ZeroByte));
	assert_eq!(compare(str::from_utf8(&[b'z'; 73])?, &h), Err(CompareError::Length));
	assert_eq!(compare(str::from_utf8(&[0; 73])?, &h), Err(CompareError::Length));
	Ok(())
}

#[test]
fn parse() {
	assert_eq!(
		"$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>()
			.map(|h| (h.work_factor, h.salt.to_bytes(), h.hash)),
		Ok((
			WorkFactor::EXP4,
			*b"\x79\x76\x2b\xe9\x97\x0f\x5b\xe7\x3a\xc7\x7c\x0e\x4f\x0a\x38\x51",
			*b"\xdb\x8f\x03\x60\xd2\xaa\x48\xe1\x41\x55\x98\xbb\xc1\xb5\xc0\xd9\x10\x30\x43\xea\x39\x68\x6a",
		)),
	);
	assert_eq!(
		"$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>()
			.map(|h| (h.work_factor, h.salt.to_bytes(), h.hash)),
		"$2a$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>()
			.map(|h| (h.work_factor, h.salt.to_bytes(), h.hash)),
	);
	assert_eq!(
		"$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>()
			.map(|h| (h.work_factor, h.salt.to_bytes(), h.hash)),
		"$2y$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>()
			.map(|h| (h.work_factor, h.salt.to_bytes(), h.hash)),
	);

	assert_eq!("".parse::<Hash>().err(), Some(ParseError::Length));
	assert_eq!("$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YE".parse::<Hash>().err(), Some(ParseError::Length));
	assert_eq!("$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEmm".parse::<Hash>().err(), Some(ParseError::Length));

	assert_eq!("$2x$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>().err(), Some(ParseError::Prefix));

	assert_eq!("$2b$0§cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>().err(), Some(ParseError::WorkFactor));
	assert_eq!("$2b$4$ccVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>().err(), Some(ParseError::WorkFactor));

	assert_eq!("$2b$04$cVWp4XaNU8a4v!uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm".parse::<Hash>().err(), Some(ParseError::Salt));
	assert_eq!("$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV,0P.uO8m3YEm".parse::<Hash>().err(), Some(ParseError::Hash));
}

const TEST_VECTORS: [(&str, &str, &str); 24] = include!("pyca-test-vectors.in");
const ROUND_TRIP_TEST_VECTORS: usize = 20;

#[test]
fn parse_round_trip() -> Result<(), Box<dyn Error>> {
	for (_, _, formatted_hash) in &TEST_VECTORS[..ROUND_TRIP_TEST_VECTORS] {
		assert_eq!(&str::from_utf8(&formatted_hash.parse::<Hash>()?.to_formatted())?, formatted_hash);
	}
	Ok(())
}

#[test]
fn pyca_test_vectors() -> Result<(), Box<dyn Error>> {
	for (key, _, formatted_hash) in &TEST_VECTORS {
		assert_eq!(compare(key, &formatted_hash.parse()?), Ok(true));
	}
	Ok(())
}
