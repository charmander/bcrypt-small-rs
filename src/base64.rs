#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Base64Error {
	InvalidCharacter,
	Length,
}

const ALPHABET: [u8; 64] = *b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const REVERSE_ALPHABET: [i8; 77] = [
	// ./
	0, 1,
	// 0-9
	54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
	// : ; < = > ? @
	-1, -1, -1, -1, -1, -1, -1,
	// A-Z
	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
	// [ \ ] ^ _ `
	-1, -1, -1, -1, -1, -1,
	// a-z
	28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
];

fn char_at(index: u8) -> u8 {
	ALPHABET[usize::from(index)]
}

fn index_for(c: u8) -> Result<u8, Base64Error> {
	match REVERSE_ALPHABET.get(usize::from(c.wrapping_sub(b'.'))) {
		None | Some(&-1) => Err(Base64Error::InvalidCharacter),
		Some(&i) => Ok(i as u8),
	}
}

pub fn encode(from: &[u8], to: &mut [u8]) {
	let mut to_iter = to.iter_mut();
	let mut chunks = from.chunks_exact(3);

	for chunk in &mut chunks {
		let b0 = chunk[0];
		let b1 = chunk[1];
		let b2 = chunk[2];

		*to_iter.next().unwrap() = char_at(b0 >> 2);
		*to_iter.next().unwrap() = char_at(((b0 & 0x03) << 4) | (b1 >> 4));
		*to_iter.next().unwrap() = char_at(((b1 & 0x0f) << 2) | (b2 >> 6));
		*to_iter.next().unwrap() = char_at(b2 & 0x3f);
	}

	let remainder = chunks.remainder();

	match remainder {
		[] => {},
		&[b0] => {
			*to_iter.next().unwrap() = char_at(b0 >> 2);
			*to_iter.next().unwrap() = char_at((b0 & 0x03) << 4);
		},
		&[b0, b1] => {
			*to_iter.next().unwrap() = char_at(b0 >> 2);
			*to_iter.next().unwrap() = char_at(((b0 & 0x03) << 4) | (b1 >> 4));
			*to_iter.next().unwrap() = char_at((b1 & 0x0f) << 2);
		},
		_ => unreachable!(),
	}
}

pub fn decode(from: &[u8], to: &mut [u8]) -> Result<(), Base64Error> {
	let mut to_iter = to.iter_mut();
	let mut chunks = from.chunks_exact(4);

	for chunk in &mut chunks {
		let i0 = index_for(chunk[0])?;
		let i1 = index_for(chunk[1])?;
		let i2 = index_for(chunk[2])?;
		let i3 = index_for(chunk[3])?;

		*to_iter.next().unwrap() = (i0 << 2) | (i1 >> 4);
		*to_iter.next().unwrap() = (i1 << 4) | (i2 >> 2);
		*to_iter.next().unwrap() = (i2 << 6) | i3;
	}

	let remainder = chunks.remainder();

	match remainder {
		[] => {},
		[_] => {
			return Err(Base64Error::Length);
		},
		&[c0, c1] => {
			let i0 = index_for(c0)?;
			let i1 = index_for(c1)?;

			*to_iter.next().unwrap() = (i0 << 2) | (i1 >> 4);
		},
		&[c0, c1, c2] => {
			let i0 = index_for(c0)?;
			let i1 = index_for(c1)?;
			let i2 = index_for(c2)?;

			*to_iter.next().unwrap() = (i0 << 2) | (i1 >> 4);
			*to_iter.next().unwrap() = (i1 << 4) | (i2 >> 2);
		},
		_ => unreachable!(),
	}

	Ok(())
}
