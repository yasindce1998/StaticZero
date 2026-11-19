//! Minimal SoapySDR FFI and safe wrappers — real SDR hardware support.
//!
//! SoapySDR is the industry-standard device abstraction: one library that
//! drives HackRF, bladeRF, USRP (via UHD), RTL-SDR, and LimeSDR through
//! their respective vendor modules. The bindings are hand-written against
//! the stable C API (`SoapySDR/Device.h`) instead of pulling an external
//! crate, keeping the dependency graph unchanged; only `libSoapySDR` is
//! needed at build and run time.
//!
//! Enabled with the `soapy` cargo feature:
//!
//! ```toml
//! [features]
//! soapy = []
//! ```
//!
//! Build with `cargo build -p staticzero-tools --features soapy` (requires
//! `libsoapysdr-dev` / `soapysdr` installed). Release binaries ship without
//! the feature; build from source for real hardware.
//!
//! Without any hardware attached, device enumeration still works and
//! returns an empty list — the library path is exercised even on CI.

#![allow(non_camel_case_types)]

use std::collections::HashMap;
use std::ffi::{c_char, c_double, c_int, c_long, c_void, CStr, CString};

// ── C API surface (only what the bridge uses) ────────────────────────────────

pub type SoapySDRDevice = c_void;
pub type SoapySDRStream = c_void;

pub const SOAPY_SDR_TX: c_int = 1;
pub const SOAPY_SDR_RX: c_int = 0;

/// Complex float32 I/Q ("CF32") — two native-endian f32 per sample.
pub const SOAPY_SDR_CF32: &str = "CF32";

/// Return code convention: 0 = success, negative = error (see
/// `last_error()`).
const SOAPY_SDR_SUCCESS: c_int = 0;

/// Field order matches the installed SoapySDR 0.8.x header exactly
/// (`size` first) — verified against /usr/include/SoapySDR/Types.h; a
/// wrong order compiles fine and segfaults at runtime.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SoapySDRKwargs {
    size: usize,
    keys: *mut *mut c_char,
    vals: *mut *mut c_char,
}

#[link(name = "SoapySDR")]
extern "C" {
    fn SoapySDRDevice_enumerate(
        args: *const SoapySDRKwargs,
        length: *mut usize,
    ) -> *mut SoapySDRKwargs;
    fn SoapySDRKwargsList_clear(args: *mut SoapySDRKwargs, length: usize);
    fn SoapySDRDevice_lastError() -> *const c_char;

    fn SoapySDRDevice_make(args: *const SoapySDRKwargs) -> *mut SoapySDRDevice;
    fn SoapySDRDevice_unmake(device: *mut SoapySDRDevice) -> c_int;

    fn SoapySDRDevice_setFrequency(
        device: *mut SoapySDRDevice,
        direction: c_int,
        channel: usize,
        frequency: c_double,
        args: *const SoapySDRKwargs,
    ) -> c_int;
    fn SoapySDRDevice_setSampleRate(
        device: *mut SoapySDRDevice,
        direction: c_int,
        channel: usize,
        rate: c_double,
    ) -> c_int;
    fn SoapySDRDevice_setBandwidth(
        device: *mut SoapySDRDevice,
        direction: c_int,
        channel: usize,
        bw: c_double,
    ) -> c_int;
    fn SoapySDRDevice_setGain(
        device: *mut SoapySDRDevice,
        direction: c_int,
        channel: usize,
        value: c_double,
    ) -> c_int;

    fn SoapySDRDevice_setupStream(
        device: *mut SoapySDRDevice,
        direction: c_int,
        format: *const c_char,
        channels: *const usize,
        numChans: usize,
        args: *const SoapySDRKwargs,
    ) -> *mut SoapySDRStream;
    fn SoapySDRDevice_closeStream(
        device: *mut SoapySDRDevice,
        stream: *mut SoapySDRStream,
    ) -> c_int;
    fn SoapySDRDevice_activateStream(
        device: *mut SoapySDRDevice,
        stream: *mut SoapySDRStream,
        flags: c_int,
        timeNs: i64,
        numElems: usize,
    ) -> c_int;
    fn SoapySDRDevice_deactivateStream(
        device: *mut SoapySDRDevice,
        stream: *mut SoapySDRStream,
        flags: c_int,
        timeNs: i64,
    ) -> c_int;
    fn SoapySDRDevice_getStreamMTU(
        device: *mut SoapySDRDevice,
        stream: *mut SoapySDRStream,
    ) -> usize;
    fn SoapySDRDevice_readStream(
        device: *mut SoapySDRDevice,
        stream: *mut SoapySDRStream,
        buffs: *mut *mut c_void,
        numElems: usize,
        flags: *mut c_int,
        timeNs: *mut i64,
        timeoutUs: c_long,
    ) -> c_int;
    fn SoapySDRDevice_writeStream(
        device: *mut SoapySDRDevice,
        stream: *mut SoapySDRStream,
        buffs: *const *const c_void,
        numElems: usize,
        flags: *mut c_int,
        timeNs: i64,
        timeoutUs: c_long,
    ) -> c_int;
}

fn last_error() -> String {
    unsafe {
        let ptr = SoapySDRDevice_lastError();
        if ptr.is_null() {
            "unknown SoapySDR error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

fn check(rc: c_int, what: &str) -> Result<(), String> {
    if rc == SOAPY_SDR_SUCCESS {
        Ok(())
    } else {
        Err(format!("{what} failed: {}", last_error()))
    }
}

/// Keyword arguments passed to `enumerate`/`make` (e.g. `driver=hackrf`).
/// Owns its C strings; the raw struct borrows them for the call duration.
/// The Vec fields point into the CStrings' heap storage, which does not
/// move when this struct is moved, so `raw` stays valid.
struct KwargList {
    _owned: Vec<CString>,
    _keys: Vec<*mut c_char>,
    _vals: Vec<*mut c_char>,
    raw: SoapySDRKwargs,
}

impl KwargList {
    fn new(pairs: &[(&str, &str)]) -> Self {
        let mut owned: Vec<CString> = Vec::with_capacity(pairs.len() * 2);
        let mut keys: Vec<*mut c_char> = Vec::with_capacity(pairs.len());
        let mut vals: Vec<*mut c_char> = Vec::with_capacity(pairs.len());
        for (key, value) in pairs {
            let key = CString::new(*key).expect("key has no NUL");
            let value = CString::new(*value).expect("value has no NUL");
            keys.push(key.as_ptr() as *mut c_char);
            vals.push(value.as_ptr() as *mut c_char);
            owned.push(key);
            owned.push(value);
        }
        let raw = if pairs.is_empty() {
            // An empty C struct initializer: null pointers, not dangling
            // Vec pointers — matches what a C caller passes.
            SoapySDRKwargs {
                size: 0,
                keys: std::ptr::null_mut(),
                vals: std::ptr::null_mut(),
            }
        } else {
            SoapySDRKwargs {
                size: pairs.len(),
                keys: keys.as_mut_ptr(),
                vals: vals.as_mut_ptr(),
            }
        };
        Self {
            _owned: owned,
            _keys: keys,
            _vals: vals,
            raw,
        }
    }

    fn empty() -> Self {
        Self::new(&[])
    }

    fn as_raw(&self) -> *const SoapySDRKwargs {
        &self.raw
    }
}

/// One enumerated device: its kwargs describe driver, serial, label.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceInfo {
    pub driver: String,
    pub label: String,
    #[serde(flatten)]
    pub kwargs: HashMap<String, String>,
}

/// Enumerate attached SDR devices. Returns an empty list when none are
/// present — the library itself is still exercised.
pub fn enumerate() -> Result<Vec<DeviceInfo>, String> {
    let args = KwargList::empty();
    let mut length: usize = 0;
    let list = unsafe { SoapySDRDevice_enumerate(args.as_raw(), &mut length) };
    if list.is_null() {
        return Err(format!("enumeration failed: {}", last_error()));
    }
    let mut devices = Vec::with_capacity(length);
    unsafe {
        for index in 0..length {
            let kwargs = &*list.add(index);
            let mut map = HashMap::new();
            for slot in 0..kwargs.size {
                let key = CStr::from_ptr(*kwargs.keys.add(slot))
                    .to_string_lossy()
                    .into_owned();
                let value = CStr::from_ptr(*kwargs.vals.add(slot))
                    .to_string_lossy()
                    .into_owned();
                map.insert(key, value);
            }
            let driver = map.get("driver").cloned().unwrap_or_default();
            let label = map.get("label").cloned().unwrap_or_default();
            devices.push(DeviceInfo {
                driver,
                label,
                kwargs: map,
            });
        }
        SoapySDRKwargsList_clear(list, length);
    }
    Ok(devices)
}

/// An open SoapySDR device. `Send`/`Sync` are sound: SoapySDR documents
/// its C API as thread-safe.
pub struct SoapyDevice {
    ptr: *mut SoapySDRDevice,
}

// The raw pointer makes this !Send/!Sync by default; SoapySDR device calls
// are thread-safe per the library's documentation.
unsafe impl Send for SoapyDevice {}
unsafe impl Sync for SoapyDevice {}

impl SoapyDevice {
    /// Open a device. `driver` selects the vendor module (hackrf,
    /// bladerf, usrp, rtlsdr, lime); `serial` optionally picks a unit.
    /// Both `None` opens the first available device.
    pub fn open(driver: Option<&str>, serial: Option<&str>) -> Result<Self, String> {
        let mut pairs: Vec<(&str, &str)> = Vec::new();
        if let Some(driver) = driver {
            if driver != "auto" {
                pairs.push(("driver", driver));
            }
        }
        if let Some(serial) = serial {
            pairs.push(("serial", serial));
        }
        let args = KwargList::new(&pairs);
        let ptr = unsafe { SoapySDRDevice_make(args.as_raw()) };
        if ptr.is_null() {
            return Err(format!(
                "no SoapySDR device for {} — run --mode list to enumerate, or build without the soapy feature for the stub device layer: {}",
                driver.unwrap_or("auto"),
                last_error()
            ));
        }
        Ok(Self { ptr })
    }

    /// Configure one direction (RX or TX): frequency, sample rate,
    /// bandwidth, and gain.
    pub fn configure(
        &self,
        direction: c_int,
        frequency_hz: u64,
        sample_rate_hz: u64,
        bandwidth_hz: u64,
        gain_db: u32,
    ) -> Result<(), String> {
        check(
            unsafe {
                SoapySDRDevice_setFrequency(
                    self.ptr,
                    direction,
                    0,
                    frequency_hz as c_double,
                    std::ptr::null(),
                )
            },
            "set_frequency",
        )?;
        check(
            unsafe {
                SoapySDRDevice_setSampleRate(self.ptr, direction, 0, sample_rate_hz as c_double)
            },
            "set_sample_rate",
        )?;
        if bandwidth_hz > 0 {
            // unsupported bandwidth is a warning, not a failure
            let _ = unsafe {
                SoapySDRDevice_setBandwidth(self.ptr, direction, 0, bandwidth_hz as c_double)
            };
        }
        check(
            unsafe { SoapySDRDevice_setGain(self.ptr, direction, 0, gain_db as c_double) },
            "set_gain",
        )?;
        Ok(())
    }

    /// Retune a direction without touching the rest of the configuration.
    pub fn set_frequency(&self, direction: c_int, frequency_hz: u64) -> Result<(), String> {
        check(
            unsafe {
                SoapySDRDevice_setFrequency(
                    self.ptr,
                    direction,
                    0,
                    frequency_hz as c_double,
                    std::ptr::null(),
                )
            },
            "set_frequency",
        )
    }

    /// Open a CF32 stream on one direction. The stream is activated
    /// immediately (SoapySDR requires activation before transfers) and
    /// deactivated/closed on drop.
    fn setup_stream(&self, direction: c_int) -> Result<SoapyStream, String> {
        let format = CString::new(SOAPY_SDR_CF32).expect("format");
        let channel: usize = 0;
        let stream = unsafe {
            SoapySDRDevice_setupStream(
                self.ptr,
                direction,
                format.as_ptr(),
                &channel,
                1,
                std::ptr::null(),
            )
        };
        if stream.is_null() {
            return Err(format!("setup_stream failed: {}", last_error()));
        }
        check(
            unsafe { SoapySDRDevice_activateStream(self.ptr, stream, 0, 0, 0) },
            "activate_stream",
        )?;
        let mtu = unsafe { SoapySDRDevice_getStreamMTU(self.ptr, stream) };
        Ok(SoapyStream {
            device: self.ptr,
            ptr: stream,
            mtu: mtu.max(1024),
        })
    }

    pub fn rx_stream(&self) -> Result<SoapyStream, String> {
        self.setup_stream(SOAPY_SDR_RX)
    }

    pub fn tx_stream(&self) -> Result<SoapyStream, String> {
        self.setup_stream(SOAPY_SDR_TX)
    }

    fn read_stream(
        &self,
        stream: &SoapyStream,
        buffer: &mut [f32],
        timeout_us: c_long,
    ) -> Result<usize, String> {
        let num_elems = buffer.len() / 2;
        let mut ptrs = [buffer.as_mut_ptr() as *mut c_void];
        let mut flags: c_int = 0;
        let mut time_ns: i64 = 0;
        let read = unsafe {
            SoapySDRDevice_readStream(
                self.ptr,
                stream.ptr,
                ptrs.as_mut_ptr(),
                num_elems,
                &mut flags,
                &mut time_ns,
                timeout_us,
            )
        };
        if read < 0 {
            return Err(format!("read_stream failed: {}", last_error()));
        }
        Ok(read as usize)
    }

    /// Blocking single-channel CF32 receive into `buffer` (interleaved
    /// I/Q pairs). Returns the number of complex elements read; `0` means
    /// the timeout elapsed with no data.
    pub fn read_into(
        &self,
        stream: &SoapyStream,
        buffer: &mut [f32],
        timeout_us: i64,
    ) -> Result<usize, String> {
        self.read_stream(stream, buffer, timeout_us as c_long)
    }

    fn write_stream(
        &self,
        stream: &SoapyStream,
        buffer: &[f32],
        timeout_us: c_long,
    ) -> Result<usize, String> {
        let num_elems = buffer.len() / 2;
        let ptrs = [buffer.as_ptr() as *const c_void];
        let mut flags: c_int = 0;
        let written = unsafe {
            SoapySDRDevice_writeStream(
                self.ptr,
                stream.ptr,
                ptrs.as_ptr(),
                num_elems,
                &mut flags,
                0,
                timeout_us,
            )
        };
        if written < 0 {
            return Err(format!("write_stream failed: {}", last_error()));
        }
        Ok(written as usize)
    }
}

impl Drop for SoapyDevice {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let _ = unsafe { SoapySDRDevice_unmake(self.ptr) };
        }
    }
}

/// An open CF32 stream (RX or TX). Reading and writing raw f32 I/Q pairs
/// through the device that created it.
pub struct SoapyStream {
    device: *mut SoapySDRDevice,
    ptr: *mut SoapySDRStream,
    mtu: usize,
}

// Streams must only be used from one thread at a time; moving one to a
// dedicated reader/transmitter thread (as the bridge does) is sound.
unsafe impl Send for SoapyStream {}

impl Drop for SoapyStream {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let _ = unsafe { SoapySDRDevice_deactivateStream(self.device, self.ptr, 0, 0) };
            let _ = unsafe { SoapySDRDevice_closeStream(self.device, self.ptr) };
        }
    }
}

impl SoapyStream {
    /// Maximum number of complex elements per transfer.
    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

/// Blocking receive loop: reads `sample_count` complex samples from an
/// activated RX stream and returns them as interleaved I/Q f32 pairs.
/// Ten consecutive read timeouts (20 s without data) abort with an error
/// so a stalled device cannot hang a scan.
pub fn receive(
    device: &SoapyDevice,
    stream: &SoapyStream,
    sample_count: usize,
) -> Result<Vec<f32>, String> {
    const MAX_CONSECUTIVE_TIMEOUTS: usize = 10;
    let mut buffer = vec![0f32; stream.mtu() * 2];
    let mut out = Vec::with_capacity(sample_count * 2);
    let mut timeouts = 0usize;
    while out.len() < sample_count * 2 {
        let read = device.read_stream(stream, &mut buffer, 2_000_000)?;
        if read == 0 {
            timeouts += 1;
            if timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                return Err("receive timed out: no samples for 20 seconds".to_string());
            }
            continue;
        }
        timeouts = 0;
        out.extend_from_slice(&buffer[..read * 2]);
    }
    Ok(out)
}

/// Transmit interleaved I/Q f32 pairs through an activated TX stream.
pub fn transmit(device: &SoapyDevice, stream: &SoapyStream, samples: &[f32]) -> Result<(), String> {
    let mtu = stream.mtu();
    for chunk in samples.chunks(mtu.max(2) * 2) {
        let mut written = 0;
        while written < chunk.len() / 2 {
            written += device.write_stream(stream, &chunk[written * 2..], 2_000_000)?;
        }
    }
    Ok(())
}

/// Mean signal power in dBFS from interleaved I/Q f32 samples.
pub fn power_dbfs(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return f32::NEG_INFINITY;
    }
    let sum: f64 = samples
        .as_chunks::<2>()
        .0
        .iter()
        .map(|iq| (iq[0] as f64) * (iq[0] as f64) + (iq[1] as f64) * (iq[1] as f64))
        .sum();
    let mean = sum / (samples.len() / 2) as f64;
    10.0 * mean.log10() as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_dbfs_matches_known_signals() {
        // Full-scale complex tone: 0 dBFS
        let tone: Vec<f32> = [1.0f32, 0.0].iter().cycle().take(200).cloned().collect();
        assert!((power_dbfs(&tone) - 0.0).abs() < 0.01);

        // Half-scale single component: total power 0.25 → −6.02 dBFS
        let tone: Vec<f32> = [0.5f32, 0.0].iter().cycle().take(200).cloned().collect();
        assert!((power_dbfs(&tone) + 6.0206).abs() < 0.01);

        // Half-amplitude on both axes: total power 0.5 → −3.01 dBFS
        let tone: Vec<f32> = [0.5f32, 0.5].iter().cycle().take(200).cloned().collect();
        assert!((power_dbfs(&tone) + 3.0103).abs() < 0.01);

        // Silence
        assert!(power_dbfs(&[0.0; 64]).is_infinite());
        assert_eq!(power_dbfs(&[]), f32::NEG_INFINITY);
    }

    #[test]
    fn enumeration_runs_against_the_real_library() {
        // Requires libSoapySDR at runtime (the soapy feature's CI job
        // installs it). With no hardware attached this must return an
        // empty list, not an error — the FFI path is fully exercised.
        match enumerate() {
            Ok(devices) => {
                for device in &devices {
                    assert!(!device.driver.is_empty());
                }
            }
            Err(error) => panic!("enumeration failed: {error}"),
        }
    }

    #[test]
    fn opening_a_missing_device_reports_a_clear_error() {
        // No CI runner has a "definitely-not-real" driver module; the
        // error must name the driver and mention enumeration.
        let error = match SoapyDevice::open(Some("no-such-driver-xyz"), None) {
            Ok(_) => panic!("missing driver must fail"),
            Err(error) => error,
        };
        assert!(error.contains("no-such-driver-xyz"));
        assert!(error.contains("--mode list"));
    }
}
