/*
 * Copyright (c) 2025 Internet Mastering & Company, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! FFI bindings for Arti Tor client for VPP integration
//!
//! This library provides a C-compatible interface to the Arti Tor client,
//! allowing VPP (written in C) to integrate with Arti (written in Rust).

use arti_client::{TorClient, TorClientConfig};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use once_cell::sync::Lazy;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

/// Global Tokio runtime for async operations
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("arti-vpp")
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime")
});

/// Opaque handle to Arti client
pub struct ArtiClient {
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
}

/// Opaque handle to a Tor stream
pub struct ArtiStream {
    stream: Mutex<arti_client::DataStream>,
}

/// Error codes returned by FFI functions
#[repr(C)]
pub enum ArtiError {
    Ok = 0,
    InvalidParameter = -1,
    InitFailed = -2,
    ConnectFailed = -3,
    IoError = -4,
    Timeout = -5,
}

/// Convert Rust string to C string (caller must free)
unsafe fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Initialize Arti client with configuration
///
/// # Arguments
/// * `config_dir` - Path to Tor configuration directory
/// * `cache_dir` - Path to Tor cache directory
///
/// # Returns
/// Opaque pointer to ArtiClient on success, null on failure
///
/// # Safety
/// Caller must ensure strings are valid UTF-8 null-terminated C strings
#[no_mangle]
pub unsafe extern "C" fn arti_init(
    config_dir: *const c_char,
    cache_dir: *const c_char,
) -> *mut c_void {
    if config_dir.is_null() || cache_dir.is_null() {
        eprintln!("arti_init: null pointer passed");
        return std::ptr::null_mut();
    }

    let config_dir_str = match CStr::from_ptr(config_dir).to_str() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("arti_init: invalid UTF-8 in config_dir");
            return std::ptr::null_mut();
        }
    };

    let cache_dir_str = match CStr::from_ptr(cache_dir).to_str() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("arti_init: invalid UTF-8 in cache_dir");
            return std::ptr::null_mut();
        }
    };

    let config_path = PathBuf::from(config_dir_str);
    let cache_path = PathBuf::from(cache_dir_str);

    // Create directories if they don't exist
    let _ = std::fs::create_dir_all(&config_path);
    let _ = std::fs::create_dir_all(&cache_path);

    // Build Tor client configuration
    let config = match TorClientConfig::builder()
        .state_dir(config_path)
        .cache_dir(cache_path)
        .build()
    {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("arti_init: failed to build config: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Create Tor client in async runtime
    let client_result = RUNTIME.block_on(async {
        TorClient::with_runtime(tor_rtcompat::PreferredRuntime::current()?)
            .config(config)
            .create_bootstrapped()
            .await
    });

    match client_result {
        Ok(client) => {
            let arti_client = Box::new(ArtiClient {
                client: Arc::new(client),
            });
            Box::into_raw(arti_client) as *mut c_void
        }
        Err(e) => {
            eprintln!("arti_init: failed to create client: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// Connect to a destination through Tor
///
/// # Arguments
/// * `client` - Opaque pointer to ArtiClient from arti_init
/// * `addr` - Target address (hostname or IP)
/// * `port` - Target port
/// * `stream_out` - Output pointer for created stream
///
/// # Returns
/// 0 on success, negative error code on failure
///
/// # Safety
/// Caller must ensure client is valid and addr is a valid C string
#[no_mangle]
pub unsafe extern "C" fn arti_connect(
    client: *mut c_void,
    addr: *const c_char,
    port: u16,
    stream_out: *mut *mut c_void,
) -> c_int {
    if client.is_null() || addr.is_null() || stream_out.is_null() {
        return ArtiError::InvalidParameter as c_int;
    }

    let arti_client = &*(client as *mut ArtiClient);

    let addr_str = match CStr::from_ptr(addr).to_str() {
        Ok(s) => s,
        Err(_) => return ArtiError::InvalidParameter as c_int,
    };

    let target = format!("{}:{}", addr_str, port);

    // Connect to target through Tor
    let connect_result = RUNTIME.block_on(async {
        arti_client
            .client
            .connect(target)
            .await
    });

    match connect_result {
        Ok(stream) => {
            let arti_stream = Box::new(ArtiStream {
                stream: Mutex::new(stream),
            });
            *stream_out = Box::into_raw(arti_stream) as *mut c_void;
            ArtiError::Ok as c_int
        }
        Err(e) => {
            eprintln!("arti_connect: failed to connect: {}", e);
            ArtiError::ConnectFailed as c_int
        }
    }
}

/// Send data on a Tor stream
///
/// # Arguments
/// * `stream` - Opaque pointer to ArtiStream
/// * `data` - Pointer to data buffer
/// * `len` - Length of data
///
/// # Returns
/// Number of bytes sent on success, negative error code on failure
///
/// # Safety
/// Caller must ensure stream is valid and data points to at least len bytes
#[no_mangle]
pub unsafe extern "C" fn arti_send(
    stream: *mut c_void,
    data: *const u8,
    len: usize,
) -> isize {
    if stream.is_null() || data.is_null() || len == 0 {
        return ArtiError::InvalidParameter as isize;
    }

    let arti_stream = &*(stream as *mut ArtiStream);
    let buf = std::slice::from_raw_parts(data, len);

    let write_result = RUNTIME.block_on(async {
        let mut stream_guard = arti_stream.stream.lock().await;
        stream_guard.write_all(buf).await?;
        stream_guard.flush().await?;
        Ok::<_, std::io::Error>(len)
    });

    match write_result {
        Ok(n) => n as isize,
        Err(e) => {
            eprintln!("arti_send: IO error: {}", e);
            ArtiError::IoError as isize
        }
    }
}

/// Receive data from a Tor stream
///
/// # Arguments
/// * `stream` - Opaque pointer to ArtiStream
/// * `buf` - Pointer to receive buffer
/// * `len` - Size of buffer
///
/// # Returns
/// Number of bytes received on success, 0 on EOF, negative error code on failure
///
/// # Safety
/// Caller must ensure stream is valid and buf points to at least len bytes
#[no_mangle]
pub unsafe extern "C" fn arti_recv(
    stream: *mut c_void,
    buf: *mut u8,
    len: usize,
) -> isize {
    if stream.is_null() || buf.is_null() || len == 0 {
        return ArtiError::InvalidParameter as isize;
    }

    let arti_stream = &*(stream as *mut ArtiStream);
    let buffer = std::slice::from_raw_parts_mut(buf, len);

    let read_result = RUNTIME.block_on(async {
        let mut stream_guard = arti_stream.stream.lock().await;
        stream_guard.read(buffer).await
    });

    match read_result {
        Ok(n) => n as isize,
        Err(e) => {
            eprintln!("arti_recv: IO error: {}", e);
            ArtiError::IoError as isize
        }
    }
}

/// Close a Tor stream
///
/// # Arguments
/// * `stream` - Opaque pointer to ArtiStream
///
/// # Safety
/// Caller must ensure stream is valid and not used after this call
#[no_mangle]
pub unsafe extern "C" fn arti_close_stream(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }

    let _ = Box::from_raw(stream as *mut ArtiStream);
    // Stream is automatically closed when dropped
}

/// Shutdown Arti client
///
/// # Arguments
/// * `client` - Opaque pointer to ArtiClient from arti_init
///
/// # Safety
/// Caller must ensure client is valid and not used after this call
#[no_mangle]
pub unsafe extern "C" fn arti_shutdown(client: *mut c_void) {
    if client.is_null() {
        return;
    }

    let _ = Box::from_raw(client as *mut ArtiClient);
    // Client is automatically cleaned up when dropped
}

/// Get the last error message (if any)
///
/// # Returns
/// C string with error message (caller must free), or null
///
/// # Safety
/// Caller must free the returned string with arti_free_string
#[no_mangle]
pub unsafe extern "C" fn arti_last_error() -> *mut c_char {
    // For now, return null. In production, implement proper error tracking
    std::ptr::null_mut()
}

/// Free a string allocated by this library
///
/// # Arguments
/// * `s` - C string to free
///
/// # Safety
/// Caller must ensure s was allocated by this library
#[no_mangle]
pub unsafe extern "C" fn arti_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = CString::from_raw(s);
}

/// Get version string
///
/// # Returns
/// Static C string with version
#[no_mangle]
pub extern "C" fn arti_version() -> *const c_char {
    const VERSION: &[u8] = b"arti-vpp-ffi 0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let ver = unsafe { CStr::from_ptr(arti_version()) };
        assert!(ver.to_str().unwrap().contains("arti-vpp-ffi"));
    }
}
