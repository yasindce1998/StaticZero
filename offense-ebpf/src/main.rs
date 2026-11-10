#![no_std]
#![no_main]
#![allow(unused_unsafe)]

mod maps;
mod rf_iot;
mod rf_lmr;
mod rf_oran_ais;
mod rf_uav_broadcast;
mod rf_wifi_rke;
mod satellite;
mod telecom;
mod telecom_5g;
mod telecom_advanced;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
