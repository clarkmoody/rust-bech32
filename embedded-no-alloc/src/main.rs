#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

use panic_halt as _;

use arrayvec::{ArrayString, ArrayVec};
use bech32::{self, u5, ComboError, FromBase32, ToBase32, Variant};
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

#[entry]
fn main() -> ! {
    let mut encoded = ArrayString::<30>::new();

    let mut base32 = ArrayVec::<u5, 30>::new();

    [0x00u8, 0x01, 0x02].write_base32(&mut base32).unwrap();

    bech32::encode_to_fmt_anycase(&mut encoded, "bech32", &base32, Variant::Bech32)
        .unwrap()
        .unwrap();
    test(&*encoded == "bech321qqqsyrhqy2a");

    hprintln!("{}", encoded).unwrap();

    let mut decoded = ArrayVec::<u5, 30>::new();

    let mut scratch = ArrayVec::<u5, 30>::new();

    let (hrp, data, variant) =
        bech32::decode_lowercase::<ComboError, _, _>(&encoded, &mut decoded, &mut scratch).unwrap();
    test(hrp == "bech32");
    let res = ArrayVec::<u8, 30>::from_base32(&data).unwrap();
    test(&res == [0x00, 0x01, 0x02].as_ref());
    test(variant == Variant::Bech32);

    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn test(result: bool) {
    if !result {
        debug::exit(debug::EXIT_FAILURE);
    }
}
