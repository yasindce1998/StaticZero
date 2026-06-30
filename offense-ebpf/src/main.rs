#![no_std]
#![no_main]
#![allow(unused_unsafe)]

mod maps;
mod telecom;
mod telecom_advanced;
mod telecom_5g;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
