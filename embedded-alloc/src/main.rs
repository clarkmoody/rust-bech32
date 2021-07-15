#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

extern crate alloc;
use panic_halt as _;

use self::alloc::string::ToString;
use self::alloc::vec;
use self::alloc::vec::Vec;
use core::alloc::Layout;

use alloc_cortex_m::CortexMHeap;
use bech32::{self, FromBase32, ToBase32, Variant};
use cortex_m::asm;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024; // in bytes

#[entry]
fn main() -> ! {
    // Initialize the allocator BEFORE you use it
    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let encoded = bech32::encode(
        "bech32",
        vec![0x00, 0x01, 0x02].to_base32(),
        Variant::Bech32,
    )
    .unwrap();
    test(encoded == "bech321qqqsyrhqy2a".to_string());

    hprintln!("{}", encoded).unwrap();

    let (hrp, data, variant) = bech32::decode(&encoded).unwrap();
    test(hrp == "bech32");
    test(Vec::<u8>::from_base32(&data).unwrap() == vec![0x00, 0x01, 0x02]);
    test(variant == Variant::Bech32);

    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn test(result: bool) {
    if !result {
        debug::exit(debug::EXIT_FAILURE);
    }
}

// define what happens in an Out Of Memory (OOM) condition
#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    hprintln!("{:?}", layout);
    asm::bkpt();

    loop {}
}
