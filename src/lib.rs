use std::error::Error;
use std::fmt;
use std::str::{self, FromStr};

use bcrypt_only::bcrypt;
pub use bcrypt_only::{KEY_SIZE_MAX, Salt, WorkFactor};
pub use bcrypt_only::BcryptError as CompareError;

mod base64;

#[cfg(test)]
mod tests;

/// The number of ASCII bytes in a `$2b$…` formatted bcrypt hash string.
pub const FORMATTED_HASH_SIZE: usize = 60;

/// A bcrypt hashing error for new hashes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashError {
	/// The password was longer than the limit of 72 UTF-8 bytes.
	Length,
	/// The password contained a NUL character (`'\0'`).
	ZeroByte,
	/// There was an error generating the salt.
	RandomError(getrandom::Error),
}

impl fmt::Display for HashError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			HashError::Length => write!(f, "password too long"),
			HashError::ZeroByte => write!(f, "password contains a NUL character"),
			HashError::RandomError(err) => write!(f, "salt generation failed: {}", err),
		}
	}
}

impl Error for HashError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			HashError::Length | HashError::ZeroByte => None,
			HashError::RandomError(err) => Some(err),
		}
	}
}

/// A bcrypt hash, comprising a work factor, salt, and digest bytes. Holds information equivalent to the `$2b$…` format created by OpenBSD’s bcrypt.
#[derive(Clone, Debug)]
pub struct Hash {
	/// The hash’s work factor.
	pub work_factor: WorkFactor,
	/// The hash’s salt.
	pub salt: Salt,
	/// The actual output of the hash.
	pub hash: [u8; 23],
}

impl Hash {
	/// Converts the hash to `$2b$…` form as exactly 60 ASCII bytes.
	///
	/// ```
	/// # use bcrypt_small::*;
	/// # use std::str;
	/// let hash = Hash {
	///     work_factor: WorkFactor::EXP4,
	///     salt: Salt::from_bytes(&[b'*'; 16]),
	///     hash: *b"\xa2\x16\x9di\xe4\x9c\xaa\xf5\xe6]0>\x81=_\\,N\xab\x0c\x00\xd3)",
	/// };
	///
	/// assert_eq!(
	///     str::from_utf8(&hash.to_formatted()).unwrap(),
	///     "$2b$04$IgmoIgmoIgmoIgmoIgmoIemfYbYcQaotVkVR.8eRzdVAvMouu.ywi"
	/// );
	/// ```
	pub fn to_formatted(&self) -> [u8; FORMATTED_HASH_SIZE] {
		let mut formatted = [0_u8; 60];
		formatted[..4].copy_from_slice(b"$2b$");
		formatted[4] = b'0' + (self.work_factor.log_rounds() / 10) as u8;
		formatted[5] = b'0' + (self.work_factor.log_rounds() % 10) as u8;
		formatted[6] = b'$';
		base64::encode(&self.salt.to_bytes(), &mut formatted[7..29]);
		base64::encode(&self.hash, &mut formatted[29..60]);
		formatted
	}
}

/// An error parsing a formatted bcrypt hash string.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParseError {
	Length,
	Prefix,
	WorkFactor,
	Salt,
	Hash,
}

impl fmt::Display for ParseError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", match self {
			ParseError::Length => "invalid length",
			ParseError::Prefix => "invalid prefix",
			ParseError::WorkFactor => "invalid work factor",
			ParseError::Salt => "invalid salt",
			ParseError::Hash => "invalid hash",
		})
	}
}

impl Error for ParseError {}

/// Parses a hash from the `$2b$…` format created by OpenBSD’s bcrypt. Also supports `$2a$` and `$2y$` prefixes from earlier and other implementations.
impl FromStr for Hash {
	type Err = ParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != 60 {
			return Err(ParseError::Length);
		}

		if !s.starts_with("$2a$") && !s.starts_with("$2b$") && !s.starts_with("$2y$") {
			return Err(ParseError::Prefix);
		}

		let work_factor =
			s.get(4..6)
				.and_then(|rs| rs.parse().ok())
				.and_then(WorkFactor::exp)
				.ok_or(ParseError::WorkFactor)?;

		let salt = {
			let mut salt = [0_u8; 16];
			base64::decode(&s.as_bytes()[7..29], &mut salt).map_err(|_| ParseError::Salt)?;
			Salt::from_bytes(&salt)
		};

		let mut hash = [0_u8; 23];
		base64::decode(&s.as_bytes()[29..60], &mut hash).map_err(|_| ParseError::Hash)?;

		Ok(Self { work_factor, salt, hash })
	}
}

/// Creates a new password hash.
pub fn hash(password: &str, work_factor: WorkFactor) -> Result<Hash, HashError> {
	if password.len() > KEY_SIZE_MAX {
		return Err(HashError::Length);
	}

	if password.contains('\0') {
		return Err(HashError::ZeroByte);
	}

	let mut salt = [0_u8; 16];
	getrandom::getrandom(&mut salt).map_err(HashError::RandomError)?;
	let salt = Salt::from_bytes(&salt);

	let hash = bcrypt(password.as_bytes(), &salt, work_factor).unwrap();
	Ok(Hash { work_factor, salt, hash })
}

/// Compares a password to an existing hash.
pub fn compare(password: &str, expected: &Hash) -> Result<bool, CompareError> {
	let hash = bcrypt(password.as_bytes(), &expected.salt, expected.work_factor)?;
	Ok(hash == expected.hash)
}
