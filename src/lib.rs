// Copyright (c) 2017 Clark Moody
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Encoding and decoding of the Bech32 format
//!
//! Bech32 is an encoding scheme that is easy to use for humans and efficient to encode in QR codes.
//!
//! A Bech32 string consists of a human-readable part (HRP), a separator (the character `'1'`), and a data part.
//! A checksum at the end of the string provides error detection to prevent mistakes when the string is written off or read out loud.
//!
//! The original description in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) has more details.
//!

#![cfg_attr(feature = "std", doc = "
# Examples

```
use bech32::{self, FromBase32};
use bech32::ToBase32;

let encoded = bech32::encode(\"bech32\", vec![0x00, 0x01, 0x02].to_base32()).unwrap();
assert_eq!(encoded, \"bech321qqqsyrhqy2a\".to_string());

let (hrp, data) = bech32::decode(&encoded).unwrap();
assert_eq!(hrp, \"bech32\");
assert_eq!(Vec::<u8>::from_base32(&data).unwrap(), vec![0x00, 0x01, 0x02]);
```
")]

// Allow trait objects without dyn on nightly and make 1.22 ignore the unknown lint
#![allow(unknown_lints)]
#![allow(bare_trait_objects)]
#![deny(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![cfg_attr(feature = "strict", deny(warnings))]
#![no_std]

use core::fmt;

extern crate void;
use void::Void;
#[cfg(feature = "std")]
use void::*;

#[cfg(feature = "std")]
extern crate std;
#[cfg(test)]
#[macro_use]
extern crate std as std_for_test;
#[cfg(feature = "std")]
use std::prelude::v1::*;

#[cfg(feature = "std")]
use std::borrow::Cow;
#[cfg(feature = "std")]
use std::error;

// AsciiExt is needed for Rust 1.14 but not for newer versions
#[allow(unused_imports, deprecated)]
#[cfg(feature = "std")]
use std::ascii::AsciiExt;

/// Integer in the range `0..32`
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub struct u5(u8);

impl u5 {
    /// Convert a `u8` to `u5` if in range, return `Error` otherwise
    pub fn try_from_u8(value: u8) -> Result<u5, Error> {
        if value > 31 {
            Err(Error::InvalidData(value))
        } else {
            Ok(u5(value))
        }
    }

    /// Returns a copy of the underlying `u8` value
    pub fn to_u8(self) -> u8 {
        self.0
    }

    /// Get char representing this 5 bit value as defined in BIP173
    pub fn to_char(self) -> char {
        CHARSET[self.to_u8() as usize]
    }
}

impl Into<u8> for u5 {
    fn into(self) -> u8 {
        self.0
    }
}

impl AsRef<u8> for u5 {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}

/// Interface to write `u(2*n)`s into a sink
pub trait WriteBaseN<T>
where
    T: Copy,
{
    /// Write error
    type Err: fmt::Debug;

    /// Write a `u5` slice
    fn write(&mut self, data: &[T]) -> Result<(), Self::Err> {
        for b in data {
            self.write_u5(*b)?;
        }
        Ok(())
    }

    /// Write a single `u5`
    fn write_u5(&mut self, data: T) -> Result<(), Self::Err> {
        self.write(&[data])
    }
}

/// Interface to write `u5`s into a sink
pub trait WriteBase32: WriteBaseN<u5> {}
impl<T> WriteBase32 for T where T: WriteBaseN<u5> {}

/// Interface to write `u8`s into a sink
///
/// Like `std::io::Writer`, but because the associated type is no_std compatible.
pub trait WriteBase256: WriteBaseN<u8> {}
impl<T> WriteBase256 for T where T: WriteBaseN<u8> {}

/// Allocationless Bech32 writer that accumulates the checksum data internally and writes them out
/// in the end.
pub struct Bech32Writer<'a> {
    formatter: &'a mut fmt::Write,
    chk: u32,
}

impl<'a> Bech32Writer<'a> {
    /// Creates a new writer that can write a bech32 string without allocating itself.
    ///
    /// This is a rather low-level API and doesn't check the HRP or data length for standard
    /// compliance.
    pub fn new(hrp: &str, fmt: &'a mut fmt::Write) -> Result<Bech32Writer<'a>, fmt::Error> {
        let mut writer = Bech32Writer {
            formatter: fmt,
            chk: 1,
        };

        writer.formatter.write_str(hrp)?;
        writer.formatter.write_char(SEP)?;

        // expand HRP
        for b in hrp.bytes() {
            writer.polymod_step(u5(b >> 5));
        }
        writer.polymod_step(u5(0));
        for b in hrp.bytes() {
            writer.polymod_step(u5(b & 0x1f));
        }

        Ok(writer)
    }

    fn polymod_step(&mut self, v: u5) {
        let b = (self.chk >> 25) as u8;
        self.chk = (self.chk & 0x01ff_ffff) << 5 ^ (u32::from(*v.as_ref()));

        for (i, item) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                self.chk ^= item;
            }
        }
    }

    /// Write out the checksum at the end. If this method isn't called this will happen on drop.
    pub fn finalize(mut self) -> fmt::Result {
        self.inner_finalize()?;
        core::mem::forget(self);
        Ok(())
    }

    fn inner_finalize(&mut self) -> fmt::Result {
        // Pad with 6 zeros
        for _ in 0..6 {
            self.polymod_step(u5(0))
        }

        let plm: u32 = self.chk ^ 1;

        for p in 0..6 {
            self.formatter
                .write_char(u5(((plm >> (5 * (5 - p))) & 0x1f) as u8).to_char())?;
        }

        Ok(())
    }
}
impl<'a> WriteBaseN<u5> for Bech32Writer<'a> {
    type Err = fmt::Error;

    /// Writes a single 5 bit value of the data part
    fn write_u5(&mut self, data: u5) -> fmt::Result {
        self.polymod_step(data);
        self.formatter.write_char(data.to_char())
    }
}

impl<'a> Drop for Bech32Writer<'a> {
    fn drop(&mut self) {
        self.inner_finalize()
            .expect("Unhandled error writing the checksum on drop.")
    }
}

/// Parse/convert base32 slice to `Self`. It is the reciprocal of
/// `ToBase32`.
pub trait FromBase32: Sized {
    /// The associated error which can be returned from parsing (e.g. because of bad padding).
    type Err;

    /// Convert a base32 slice to `Self`.
    fn from_base32(b32: &[u5]) -> Result<Self, Self::Err>;
}

#[cfg(feature = "std")]
impl<T: Copy> WriteBaseN<T> for Vec<T> {
    type Err = Void;

    fn write(&mut self, data: &[T]) -> Result<(), Self::Err> {
        self.extend_from_slice(data);
        Ok(())
    }

    fn write_u5(&mut self, data: T) -> Result<(), Self::Err> {
        self.push(data);
        Ok(())
    }
}

#[cfg(feature = "std")]
impl FromBase32 for Vec<u8> {
    type Err = Error;

    /// Convert base32 to base256, removes null-padding if present, returns
    /// `Err(Error::InvalidPadding)` if padding bits are unequal `0`
    fn from_base32(b32: &[u5]) -> Result<Self, Self::Err> {
        convert_bits(b32, 5, 8, false)
    }
}

/// A trait for converting a value to a type `T` that represents a `u5` slice.
pub trait ToBase32 {
    /// Convert `Self` to base32 vector
    #[cfg(feature = "std")]
    fn to_base32(&self) -> Vec<u5> {
        let mut vec = Vec::new();
        self.write_base32(&mut vec).unwrap();
        vec
    }

    /// Encode as base32 and write it to the supplied writer
    /// Implementations shouldn't allocate.
    fn write_base32<W: WriteBase32>(
        &self,
        writer: &mut W,
    ) -> Result<(), <W as WriteBaseN<u5>>::Err>;
}

/// Interface to calculate the length of the base32 representation before actually serializing
pub trait Base32Len: ToBase32 {
    /// Calculate the base32 serialized length
    fn base32_len(&self) -> usize;
}

impl<T: AsRef<[u8]>> ToBase32 for T {
    fn write_base32<W: WriteBase32>(
        &self,
        writer: &mut W,
    ) -> Result<(), <W as WriteBaseN<u5>>::Err> {
        // Amount of bits left over from last round, stored in buffer.
        let mut buffer_bits = 0u32;
        // Holds all unwritten bits left over from last round. The bits are stored beginning from
        // the most significant bit. E.g. if buffer_bits=3, then the byte with bits a, b and c will
        // look as follows: [a, b, c, 0, 0, 0, 0, 0]
        let mut buffer: u8 = 0;

        for &b in self.as_ref() {
            // Write first u5 if we have to write two u5s this round. That only happens if the
            // buffer holds too many bits, so we don't have to combine buffer bits with new bits
            // from this rounds byte.
            if buffer_bits >= 5 {
                writer.write_u5(u5((buffer & 0b1111_1000) >> 3))?;
                buffer <<= 5;
                buffer_bits -= 5;
            }

            // Combine all bits from buffer with enough bits from this rounds byte so that they fill
            // a u5. Save reamining bits from byte to buffer.
            let from_buffer = buffer >> 3;
            let from_byte = b >> (3 + buffer_bits); // buffer_bits <= 4

            writer.write_u5(u5(from_buffer | from_byte))?;
            buffer = b << (5 - buffer_bits);
            buffer_bits += 3;
        }

        // There can be at most two u5s left in the buffer after processing all bytes, write them.
        if buffer_bits >= 5 {
            writer.write_u5(u5((buffer & 0b1111_1000) >> 3))?;
            buffer <<= 5;
            buffer_bits -= 5;
        }

        if buffer_bits != 0 {
            writer.write_u5(u5(buffer >> 3))?;
        }

        Ok(())
    }
}

impl<T: AsRef<[u8]>> Base32Len for T {
    fn base32_len(&self) -> usize {
        let bits = self.as_ref().len() * 8;
        if bits % 5 == 0 {
            bits / 5
        } else {
            bits / 5 + 1
        }
    }
}

/// A trait to convert between u8 arrays and u5 arrays without changing the content of the elements,
/// but checking that they are in range.
pub trait CheckBase32<T> {
    /// Error type if conversion fails
    type Err;

    /// Check if all values are in range and return array-like struct of `u5` values
    fn check_base32(self) -> Result<T, Self::Err>;
}

impl<'f, T, U: AsRef<[u8]>> CheckBase32<T> for U
where
    T: AsRef<[u5]>,
    T: core::iter::FromIterator<u5>,
{
    type Err = Error;

    fn check_base32(self) -> Result<T, Self::Err> {
        self.as_ref()
            .iter()
            .map(|x| u5::try_from_u8(*x))
            .collect::<Result<T, Error>>()
    }
}

impl<'f, U: AsRef<[u8]>> CheckBase32<()> for U {
    type Err = Error;

    fn check_base32(self) -> Result<(), Error> {
        self.as_ref()
            .iter()
            .map(|x| u5::try_from_u8(*x).map(|_| ()))
            .find(|r| r.is_err())
            .unwrap_or(Ok(()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Upper,
    Lower,
    None,
}

/// Check if the HRP is valid. Returns the case of the HRP, if any.
///
/// # Errors
/// * **MixedCase**: If the HRP contains both uppercase and lowercase characters.
/// * **InvalidChar**: If the HRP contains any non-ASCII characters (outside 33..=126).
/// * **InvalidLength**: If the HRP is outside 1..83 characters long.
fn check_hrp(hrp: &str) -> Result<Case, Error> {
    if hrp.is_empty() || hrp.len() > 83 {
        return Err(Error::InvalidLength);
    }

    let mut has_lower: bool = false;
    let mut has_upper: bool = false;
    for b in hrp.bytes() {
        // Valid subset of ASCII
        if b < 33 || b > 126 {
            return Err(Error::InvalidChar(b as char));
        }

        if b >= b'a' && b <= b'z' {
            has_lower = true;
        } else if b >= b'A' && b <= b'Z' {
            has_upper = true;
        };

        if has_lower && has_upper {
            return Err(Error::MixedCase);
        }
    }

    Ok(match (has_upper, has_lower) {
        (true, false) => Case::Upper,
        (false, true) => Case::Lower,
        (false, false) => Case::None,
        (true, true) => unreachable!(),
    })
}

/// Encode a bech32 payload to an [fmt::Write].
/// This method is intended for implementing traits from [std::fmt].
///
/// # Errors
/// * If [check_hrp] returns an error for the given HRP.
/// # Deviations from standard
/// * No length limits are enforced for the data part
#[cfg(feature = "std")]
pub fn encode_to_fmt<T: AsRef<[u5]>>(
    fmt: &mut fmt::Write,
    hrp: &str,
    data: T,
) -> Result<fmt::Result, Error> {
    let hrp_lower = match check_hrp(&hrp)? {
        Case::Upper => Cow::Owned(hrp.to_lowercase()),
        Case::Lower | Case::None => Cow::Borrowed(hrp),
    };

    encode_to_fmt_anycase(fmt, &hrp_lower, data)
}

/// Encode a bech32 payload to an [fmt::Write], but with any case.
/// This method is intended for implementing traits from [core::fmt] without [std].
///
/// See `encode_to_fmt` for meaning of errors.
pub fn encode_to_fmt_anycase<T: AsRef<[u5]>>(
    fmt: &mut fmt::Write,
    hrp: &str,
    data: T,
) -> Result<fmt::Result, Error> {
    match Bech32Writer::new(&hrp, fmt) {
        Ok(mut writer) => {
            Ok(writer.write(data.as_ref()).and_then(|_| {
                // Finalize manually to avoid panic on drop if write fails
                writer.finalize()
            }))
        }
        Err(e) => Ok(Err(e)),
    }
}

/// Encode a bech32 payload to string.
///
/// # Errors
/// * If [check_hrp] returns an error for the given HRP.
/// # Deviations from standard
/// * No length limits are enforced for the data part
#[cfg(feature = "std")]
pub fn encode<T: AsRef<[u5]>>(hrp: &str, data: T) -> Result<String, Error> {
    let mut buf = String::new();
    encode_to_fmt(&mut buf, hrp, data)?.unwrap();
    Ok(buf)
}

/// Decode a bech32 string into the raw HRP and the data bytes.
///
/// Returns the HRP in lowercase..
#[cfg(feature = "std")]
pub fn decode(s: &str) -> Result<(String, Vec<u5>), Error> {
    // Ensure overall length is within bounds
    if s.len() < 8 {
        return Err(Error::InvalidLength);
    }

    // Split at separator and check for two pieces
    let (raw_hrp, raw_data) = match s.rfind(SEP) {
        None => return Err(Error::MissingSeparator),
        Some(sep) => {
            let (hrp, data) = s.split_at(sep);
            (hrp, &data[1..])
        }
    };
    if raw_data.len() < 6 {
        return Err(Error::InvalidLength);
    }

    let mut case = check_hrp(&raw_hrp)?;
    let hrp_lower = match case {
        Case::Upper => raw_hrp.to_lowercase(),
        // already lowercase
        Case::Lower | Case::None => String::from(raw_hrp),
    };

    // Check data payload
    let mut data = raw_data
        .chars()
        .map(|c| {
            // Only check if c is in the ASCII range, all invalid ASCII
            // characters have the value -1 in CHARSET_REV (which covers
            // the whole ASCII range) and will be filtered out later.
            if !c.is_ascii() {
                return Err(Error::InvalidChar(c));
            }

            if c.is_lowercase() {
                match case {
                    Case::Upper => return Err(Error::MixedCase),
                    Case::None => case = Case::Lower,
                    Case::Lower => {}
                }
            } else if c.is_uppercase() {
                match case {
                    Case::Lower => return Err(Error::MixedCase),
                    Case::None => case = Case::Upper,
                    Case::Upper => {}
                }
            }

            // c should be <128 since it is in the ASCII range, CHARSET_REV.len() == 128
            let num_value = CHARSET_REV[c as usize];

            if num_value > 31 || num_value < 0 {
                return Err(Error::InvalidChar(c));
            }

            Ok(u5::try_from_u8(num_value as u8).expect("range checked above, num_value <= 31"))
        })
        .collect::<Result<Vec<u5>, Error>>()?;

    // Ensure checksum
    if !verify_checksum(&hrp_lower.as_bytes(), &data) {
        return Err(Error::InvalidChecksum);
    }

    // Remove checksum from data payload
    let dbl: usize = data.len();
    data.truncate(dbl - 6);

    Ok((hrp_lower, data))
}

// TODO deduplicate some
/// Decode a lowercase bech32 string into the raw HRP and the data bytes.
///
/// Less flexible than [decode], but don't allocate.
pub fn decode_lowercase<'a, 'b, R, S>(
    s: &'a str,
    data: &'b mut R,
    scratch: &mut S,
) -> Result<(&'a str, &'b [u5]), Error>
where
    R: WriteBase32 + AsRef<[u5]>,
    S: WriteBase32 + AsRef<[u5]>,
    Error: From<R::Err>,
    Error: From<S::Err>,
{
    // Ensure overall length is within bounds
    if s.len() < 8 {
        return Err(Error::InvalidLength);
    }

    // Split at separator and check for two pieces
    let (hrp_lower, raw_data) = match s.rfind(SEP) {
        None => return Err(Error::MissingSeparator),
        Some(sep) => {
            let (hrp, data) = s.split_at(sep);
            (hrp, &data[1..])
        }
    };
    if raw_data.len() < 6 {
        return Err(Error::InvalidLength);
    }

    let case = match check_hrp(&hrp_lower)? {
        Case::Upper => return Err(Error::MixedCase),
        // already lowercase
        Case::Lower | Case::None => Case::Lower,
    };

    // Check data payload
    for c in raw_data.chars() {
        // Only check if c is in the ASCII range, all invalid ASCII
        // characters have the value -1 in CHARSET_REV (which covers
        // the whole ASCII range) and will be filtered out later.
        if !c.is_ascii() {
            return Err(Error::InvalidChar(c));
        }

        match case {
            Case::Upper => return Err(Error::MixedCase),
            Case::None | Case::Lower => {},
        }

        // c should be <128 since it is in the ASCII range, CHARSET_REV.len() == 128
        let num_value = CHARSET_REV[c as usize];

        if num_value > 31 || num_value < 0 {
            return Err(Error::InvalidChar(c));
        }

        data.write_u5(
            u5::try_from_u8(num_value as u8).expect("range checked above, num_value <= 31"),
        )?;
    }

    // Ensure checksum
    if !verify_checksum_in(&hrp_lower.as_bytes(), data.as_ref(), scratch)? {
        return Err(Error::InvalidChecksum);
    }

    let dbl: usize = data.as_ref().len();
    Ok((
        hrp_lower,
        &(*data).as_ref()[..dbl.saturating_sub(6)],
    ))
}

#[cfg(feature = "std")]
fn verify_checksum(hrp: &[u8], data: &[u5]) -> bool {
    let mut v: Vec<u5> = Vec::new();
    verify_checksum_in(hrp, data, &mut v).void_unwrap()
}

fn verify_checksum_in<T>(hrp: &[u8], data: &[u5], v: &mut T) -> Result<bool, T::Err>
where
    T: WriteBase32 + AsRef<[u5]>,
{
    hrp_expand_in(hrp, v)?;
    v.write(data)?;
    Ok(polymod(v.as_ref()) == 1u32)
}

fn hrp_expand_in<T: WriteBase32>(hrp: &[u8], v: &mut T) -> Result<(), T::Err> {
    for b in hrp {
        v.write_u5(u5::try_from_u8(*b >> 5).expect("can't be out of range, max. 7"))?;
    }
    v.write_u5(u5::try_from_u8(0).unwrap())?;
    for b in hrp {
        v.write_u5(u5::try_from_u8(*b & 0x1f).expect("can't be out of range, max. 31"))?;
    }
    Ok(())
}

fn polymod(values: &[u5]) -> u32 {
    let mut chk: u32 = 1;
    let mut b: u8;
    for v in values {
        b = (chk >> 25) as u8;
        chk = (chk & 0x01ff_ffff) << 5 ^ (u32::from(*v.as_ref()));

        for (i, item) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= item;
            }
        }
    }
    chk
}

/// Human-readable part and data part separator
const SEP: char = '1';

/// Encoding character set. Maps data value -> char
const CHARSET: [char; 32] = [
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8', //  +0
    'g', 'f', '2', 't', 'v', 'd', 'w', '0', //  +8
    's', '3', 'j', 'n', '5', '4', 'k', 'h', // +16
    'c', 'e', '6', 'm', 'u', 'a', '7', 'l', // +24
];

/// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

/// Generator coefficients
const GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// Error types for Bech32 encoding / decoding
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Error {
    /// String does not contain the separator character
    MissingSeparator,
    /// The checksum does not match the rest of the data
    InvalidChecksum,
    /// The data or human-readable part is too long or too short
    InvalidLength,
    /// Some part of the string contains an invalid character
    InvalidChar(char),
    /// Some part of the data has an invalid value
    InvalidData(u8),
    /// The bit conversion failed due to a padding issue
    InvalidPadding,
    /// The whole string must be of one case
    MixedCase,
}

impl From<Void> for Error {
    fn from(v: Void) -> Self {
        match v {}
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::MissingSeparator => write!(f, "missing human-readable separator, \"{}\"", SEP),
            Error::InvalidChecksum => write!(f, "invalid checksum"),
            Error::InvalidLength => write!(f, "invalid length"),
            Error::InvalidChar(n) => write!(f, "invalid character (code={})", n),
            Error::InvalidData(n) => write!(f, "invalid data point ({})", n),
            Error::InvalidPadding => write!(f, "invalid padding"),
            Error::MixedCase => write!(f, "mixed-case strings not allowed"),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::MissingSeparator => "missing human-readable separator",
            Error::InvalidChecksum => "invalid checksum",
            Error::InvalidLength => "invalid length",
            Error::InvalidChar(_) => "invalid character",
            Error::InvalidData(_) => "invalid data point",
            Error::InvalidPadding => "invalid padding",
            Error::MixedCase => "mixed-case strings not allowed",
        }
    }
}

/// Convert between bit sizes
///
/// # Errors
/// * `Error::InvalidData` if any element of `data` is out of range
/// * `Error::InvalidPadding` if `pad == false` and the padding bits are not `0`
///
/// # Panics
/// Function will panic if attempting to convert `from` or `to` a bit size that
/// is 0 or larger than 8 bits.
///
/// # Examples
///
/// ```rust
/// use bech32::convert_bits;
/// let base5 = convert_bits(&[0xff], 8, 5, true);
/// assert_eq!(base5.unwrap(), vec![0x1f, 0x1c]);
/// ```
#[cfg(feature = "std")]
pub fn convert_bits<T>(data: &[T], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, Error>
where
    T: Into<u8> + Copy,
{
    let mut ret: Vec<u8> = Vec::new();
    convert_bits_in(data, from, to, pad, &mut ret)?;
    Ok(ret)
}

/// Convert between bit sizes without allocating
///
/// Like [convert_bits].
pub fn convert_bits_in<T, R>(
    data: &[T],
    from: u32,
    to: u32,
    pad: bool,
    ret: &mut R,
) -> Result<(), Error>
where
    T: Into<u8> + Copy,
    R: WriteBase256,
    Error: From<R::Err>,
{
    if from > 8 || to > 8 || from == 0 || to == 0 {
        panic!("convert_bits `from` and `to` parameters 0 or greater than 8");
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    for value in data {
        let v: u32 = u32::from(Into::<u8>::into(*value));
        if (v >> from) != 0 {
            // Input value exceeds `from` bit size
            return Err(Error::InvalidData(v as u8));
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.write_u5(((acc >> bits) & maxv) as u8)?;
        }
    }
    if pad {
        if bits > 0 {
            ret.write_u5(((acc << (to - bits)) & maxv) as u8)?;
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(Error::InvalidPadding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use std_for_test as std;
    #[cfg(not(feature = "std"))]
    use self::std::prelude::v1::*;

    trait TextExt {
        fn check_base32_vec(self) -> Result<Vec<u5>, Error>;
    }
    impl<U: AsRef<[u8]>> TextExt for U {
        fn check_base32_vec(self) -> Result<Vec<u5>, Error> {
            self.check_base32()
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn getters_in() {
        let mut data_scratch = Vec::new();
        let mut scratch = Vec::new();
        let decoded = decode_lowercase("bc1sw50qa3jx3s", &mut data_scratch, &mut scratch).unwrap();
        let data = [16, 14, 20, 15, 0].check_base32_vec().unwrap();
        assert_eq!(decoded.0, "bc");
        assert_eq!(decoded.1, data.as_slice());
    }

    #[test]
    #[cfg(feature = "std")]
    fn getters() {
        let decoded = decode("BC1SW50QA3JX3S").unwrap();
        let data = [16, 14, 20, 15, 0].check_base32_vec().unwrap();
        assert_eq!(&decoded.0, "bc");
        assert_eq!(decoded.1, data.as_slice());
    }

    #[test]
    #[cfg(feature = "std")]
    fn valid_checksum() {
        let strings: Vec<&str> = vec!(
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        );
        for s in strings {
            let decode_result = decode(s);
            if !decode_result.is_ok() {
                panic!(
                    "Did not decode: {:?} Reason: {:?}",
                    s,
                    decode_result.unwrap_err()
                );
            }
            assert!(decode_result.is_ok());
            let decoded = decode_result.unwrap();
            let encode_result = encode(&decoded.0, decoded.1).unwrap();
            assert_eq!(s.to_lowercase(), encode_result.to_lowercase());
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn invalid_strings() {
        let pairs: Vec<(&str, Error)> = vec!(
            (" 1nwldj5",
                Error::InvalidChar(' ')),
            ("abc1\u{2192}axkwrx",
                Error::InvalidChar('\u{2192}')),
            ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
                Error::InvalidLength),
            ("pzry9x0s0muk",
                Error::MissingSeparator),
            ("1pzry9x0s0muk",
                Error::InvalidLength),
            ("x1b4n0q5v",
                Error::InvalidChar('b')),
            ("ABC1DEFGOH",
                Error::InvalidChar('O')),
            ("li1dgmt3",
                Error::InvalidLength),
            ("de1lg7wt\u{ff}",
                Error::InvalidChar('\u{ff}')),
        );
        for p in pairs {
            let (s, expected_error) = p;
            let dec_result = decode(s);
            if dec_result.is_ok() {
                println!("{:?}", dec_result.unwrap());
                panic!("Should be invalid: {:?}", s);
            }
            assert_eq!(
                dec_result.unwrap_err(),
                expected_error,
                "testing input '{}'",
                s
            );
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn valid_conversion() {
        // Set of [data, from_bits, to_bits, pad, result]
        let tests: Vec<(Vec<u8>, u32, u32, bool, Vec<u8>)> = vec![
            (vec![0x01], 1, 1, true, vec![0x01]),
            (vec![0x01, 0x01], 1, 1, true, vec![0x01, 0x01]),
            (vec![0x01], 8, 8, true, vec![0x01]),
            (vec![0x01], 8, 4, true, vec![0x00, 0x01]),
            (vec![0x01], 8, 2, true, vec![0x00, 0x00, 0x00, 0x01]),
            (
                vec![0x01],
                8,
                1,
                true,
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            ),
            (vec![0xff], 8, 5, true, vec![0x1f, 0x1c]),
            (vec![0x1f, 0x1c], 5, 8, false, vec![0xff]),
        ];
        for t in tests {
            let (data, from_bits, to_bits, pad, expected_result) = t;
            let result = convert_bits(&data, from_bits, to_bits, pad);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_result);
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn invalid_conversion() {
        // Set of [data, from_bits, to_bits, pad, expected error]
        let tests: Vec<(Vec<u8>, u32, u32, bool, Error)> = vec![
            (vec![0xff], 8, 5, false, Error::InvalidPadding),
            (vec![0x02], 1, 1, true, Error::InvalidData(0x02)),
        ];
        for t in tests {
            let (data, from_bits, to_bits, pad, expected_error) = t;
            let result = convert_bits(&data, from_bits, to_bits, pad);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), expected_error);
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn convert_bits_invalid_bit_size() {
        use std::panic::{catch_unwind, set_hook, take_hook};

        let invalid = &[(0, 8), (5, 0), (9, 5), (8, 10), (0, 16)];

        for &(from, to) in invalid {
            set_hook(Box::new(|_| {}));
            let result = catch_unwind(|| {
                let _ = convert_bits(&[0], from, to, true);
            });
            let _ = take_hook();
            assert!(result.is_err());
        }
    }

    #[test]
    fn check_base32() {
        assert!([0u8, 1, 2, 30, 31].check_base32_vec().is_ok());
        assert!([0u8, 1, 2, 30, 31, 32].check_base32_vec().is_err());
        assert!([0u8, 1, 2, 30, 31, 255].check_base32_vec().is_err());

        assert!([1u8, 2, 3, 4].check_base32_vec().is_ok());
        assert_eq!(
            [30u8, 31, 35, 20].check_base32_vec(),
            Err(Error::InvalidData(35))
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_encode() {
        assert_eq!(
            encode("", vec![1u8, 2, 3, 4].check_base32_vec().unwrap()),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn from_base32() {
        use FromBase32;
        assert_eq!(
            Vec::from_base32(&[0x1f, 0x1c].check_base32_vec().unwrap()),
            Ok(vec![0xff])
        );
        assert_eq!(
            Vec::from_base32(&[0x1f, 0x1f].check_base32_vec().unwrap()),
            Err(Error::InvalidPadding)
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn to_base32() {
        use ToBase32;
        assert_eq!(
            [0xffu8].to_base32(),
            [0x1f, 0x1c].check_base32_vec().unwrap()
        );
    }

    #[test]
    fn reverse_charset() {
        use CHARSET_REV;

        fn get_char_value(c: char) -> i8 {
            let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
            match charset.find(c.to_ascii_lowercase()) {
                Some(x) => x as i8,
                None => -1,
            }
        }

        let expected_rev_charset = (0u8..128)
            .map(|i| get_char_value(i as char))
            .collect::<Vec<_>>();

        assert_eq!(&(CHARSET_REV[..]), expected_rev_charset.as_slice());
    }

    #[test]
    #[cfg(feature = "std")]
    fn writer() {
        let hrp = "lnbc";
        let data = "Hello World!".as_bytes().to_base32();

        let mut written_str = String::new();
        {
            let mut writer = Bech32Writer::new(hrp, &mut written_str).unwrap();
            writer.write(&data).unwrap();
            writer.finalize().unwrap();
        }

        let encoded_str = encode(hrp, data).unwrap();

        assert_eq!(encoded_str, written_str);
    }

    #[test]
    #[cfg(feature = "std")]
    fn write_on_drop() {
        let hrp = "lntb";
        let data = "Hello World!".as_bytes().to_base32();

        let mut written_str = String::new();
        {
            let mut writer = Bech32Writer::new(hrp, &mut written_str).unwrap();
            writer.write(&data).unwrap();
        }

        let encoded_str = encode(hrp, data).unwrap();

        assert_eq!(encoded_str, written_str);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_hrp_case() {
        // Tests for issue with HRP case checking being ignored for encoding
        use ToBase32;
        let encoded_str = encode("HRP", [0x00, 0x00].to_base32()).unwrap();

        assert_eq!(encoded_str, "hrp1qqqq40atq3");
    }
}
