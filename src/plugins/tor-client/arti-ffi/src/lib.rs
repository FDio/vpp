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
//!
//! Production-ready implementation with:
//! - Non-blocking I/O via channels
//! - Event notification via eventfd
//! - Thread-safe operations
//! - Proper error handling

use arti_client::{TorClient, TorClientConfig};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;

/// Global Tokio runtime for async operations
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("arti-vpp")
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime")
});

/// Thread-local error storage
thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

fn set_last_error(err: String) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(err));
}

/// Opaque handle to Arti client
pub struct ArtiClient {
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
}

/// Stream state for non-blocking I/O
pub struct ArtiStream {
    stream: Arc<TokioMutex<arti_client::DataStream>>,
    /// Receive buffer (data from Tor)
    rx_buffer: Arc<StdMutex<VecDeque<u8>>>,
    /// Transmit buffer (data to Tor)
    tx_buffer: Arc<StdMutex<VecDeque<u8>>>,
    /// Event FD for signaling data availability
    event_fd: RawFd,
    /// Flag indicating if stream is closed
    closed: Arc<StdMutex<bool>>,
    /// Background task handle
    _task_handle: tokio::task::JoinHandle<()>,
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
    WouldBlock = -6,
    Closed = -7,
}

/// Create eventfd for signaling
fn create_eventfd() -> Result<RawFd, std::io::Error> {
    unsafe {
        let fd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }
}

/// Signal eventfd (write 1)
fn signal_eventfd(fd: RawFd) {
    unsafe {
        let val: u64 = 1;
        libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
    }
}

/// Clear eventfd (read and discard)
fn clear_eventfd(fd: RawFd) {
    unsafe {
        let mut val: u64 = 0;
        libc::read(fd, &mut val as *mut u64 as *mut libc::c_void, 8);
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
        set_last_error("null pointer passed to arti_init".to_string());
        return std::ptr::null_mut();
    }

    let config_dir_str = match CStr::from_ptr(config_dir).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in config_dir: {}", e));
            return std::ptr::null_mut();
        }
    };

    let cache_dir_str = match CStr::from_ptr(cache_dir).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in cache_dir: {}", e));
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
            set_last_error(format!("failed to build config: {}", e));
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
            set_last_error(format!("failed to create client: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Connect to a destination through Tor
///
/// This creates a stream and spawns a background task for I/O.
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
        set_last_error("invalid parameter in arti_connect".to_string());
        return ArtiError::InvalidParameter as c_int;
    }

    let arti_client = &*(client as *mut ArtiClient);

    let addr_str = match CStr::from_ptr(addr).to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in address: {}", e));
            return ArtiError::InvalidParameter as c_int;
        }
    };

    let target = format!("{}:{}", addr_str, port);

    // Create eventfd for signaling
    let event_fd = match create_eventfd() {
        Ok(fd) => fd,
        Err(e) => {
            set_last_error(format!("failed to create eventfd: {}", e));
            return ArtiError::IoError as c_int;
        }
    };

    // Connect to target through Tor
    let client_arc = arti_client.client.clone();
    let connect_result = RUNTIME.block_on(async move {
        client_arc.connect(target).await
    });

    match connect_result {
        Ok(stream) => {
            let stream_arc = Arc::new(TokioMutex::new(stream));
            let rx_buffer = Arc::new(StdMutex::new(VecDeque::new()));
            let tx_buffer = Arc::new(StdMutex::new(VecDeque::new()));
            let closed = Arc::new(StdMutex::new(false));

            // Spawn background I/O task
            let stream_clone = stream_arc.clone();
            let rx_clone = rx_buffer.clone();
            let tx_clone = tx_buffer.clone();
            let closed_clone = closed.clone();
            let event_fd_clone = event_fd;

            let task_handle = RUNTIME.spawn(async move {
                stream_io_task(stream_clone, rx_clone, tx_clone, closed_clone, event_fd_clone).await;
            });

            let arti_stream = Box::new(ArtiStream {
                stream: stream_arc,
                rx_buffer,
                tx_buffer,
                event_fd,
                closed,
                _task_handle: task_handle,
            });

            *stream_out = Box::into_raw(arti_stream) as *mut c_void;
            ArtiError::Ok as c_int
        }
        Err(e) => {
            unsafe { libc::close(event_fd); }
            set_last_error(format!("failed to connect: {}", e));
            ArtiError::ConnectFailed as c_int
        }
    }
}

/// Background task for stream I/O
async fn stream_io_task(
    stream: Arc<TokioMutex<arti_client::DataStream>>,
    rx_buffer: Arc<StdMutex<VecDeque<u8>>>,
    tx_buffer: Arc<StdMutex<VecDeque<u8>>>,
    closed: Arc<StdMutex<bool>>,
    event_fd: RawFd,
) {
    let mut read_buf = vec![0u8; 8192];
    let mut write_buf = Vec::new();

    loop {
        // Check if closed
        if *closed.lock().unwrap() {
            break;
        }

        let mut stream_guard = stream.lock().await;

        // Try to read from Tor stream
        match stream_guard.read(&mut read_buf).await {
            Ok(0) => {
                // EOF - stream closed by remote
                *closed.lock().unwrap() = true;
                signal_eventfd(event_fd);
                break;
            }
            Ok(n) => {
                // Data received, push to rx_buffer
                let mut rx = rx_buffer.lock().unwrap();
                rx.extend(&read_buf[..n]);
                drop(rx);
                signal_eventfd(event_fd);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, continue
            }
            Err(e) => {
                // Error occurred
                eprintln!("Tor stream read error: {}", e);
                *closed.lock().unwrap() = true;
                signal_eventfd(event_fd);
                break;
            }
        }

        // Try to write to Tor stream
        let mut tx = tx_buffer.lock().unwrap();
        if !tx.is_empty() {
            write_buf.clear();
            write_buf.extend(tx.iter());
            drop(tx);

            match stream_guard.write_all(&write_buf).await {
                Ok(_) => {
                    let mut tx = tx_buffer.lock().unwrap();
                    tx.drain(..write_buf.len());
                }
                Err(e) => {
                    eprintln!("Tor stream write error: {}", e);
                    *closed.lock().unwrap() = true;
                    signal_eventfd(event_fd);
                    break;
                }
            }
        }

        drop(stream_guard);

        // Small sleep to avoid busy-wait
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
    }
}

/// Send data on a Tor stream (non-blocking)
///
/// Enqueues data to be sent by background task.
///
/// # Arguments
/// * `stream` - Opaque pointer to ArtiStream
/// * `data` - Pointer to data buffer
/// * `len` - Length of data
///
/// # Returns
/// Number of bytes enqueued on success, negative error code on failure
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
        set_last_error("invalid parameter in arti_send".to_string());
        return ArtiError::InvalidParameter as isize;
    }

    let arti_stream = &*(stream as *mut ArtiStream);

    // Check if closed
    if *arti_stream.closed.lock().unwrap() {
        set_last_error("stream is closed".to_string());
        return ArtiError::Closed as isize;
    }

    let buf = std::slice::from_raw_parts(data, len);

    // Enqueue to tx_buffer
    let mut tx = arti_stream.tx_buffer.lock().unwrap();
    tx.extend(buf);

    len as isize
}

/// Receive data from a Tor stream (non-blocking)
///
/// Reads from receive buffer populated by background task.
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
        set_last_error("invalid parameter in arti_recv".to_string());
        return ArtiError::InvalidParameter as isize;
    }

    let arti_stream = &*(stream as *mut ArtiStream);
    let buffer = std::slice::from_raw_parts_mut(buf, len);

    let mut rx = arti_stream.rx_buffer.lock().unwrap();

    if rx.is_empty() {
        // Check if stream is closed
        if *arti_stream.closed.lock().unwrap() {
            return 0; // EOF
        }
        // No data available
        set_last_error("would block".to_string());
        return ArtiError::WouldBlock as isize;
    }

    // Read available data
    let to_read = std::cmp::min(len, rx.len());
    for i in 0..to_read {
        buffer[i] = rx.pop_front().unwrap();
    }

    to_read as isize
}

/// Get event file descriptor for stream
///
/// This FD can be polled by VPP to detect when data is available.
///
/// # Arguments
/// * `stream` - Opaque pointer to ArtiStream
///
/// # Returns
/// File descriptor or -1 on error
///
/// # Safety
/// Caller must ensure stream is valid
#[no_mangle]
pub unsafe extern "C" fn arti_stream_get_fd(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return -1;
    }

    let arti_stream = &*(stream as *mut ArtiStream);
    arti_stream.event_fd as c_int
}

/// Clear event notification on stream
///
/// Call this after being notified of data availability.
///
/// # Arguments
/// * `stream` - Opaque pointer to ArtiStream
///
/// # Safety
/// Caller must ensure stream is valid
#[no_mangle]
pub unsafe extern "C" fn arti_stream_clear_event(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }

    let arti_stream = &*(stream as *mut ArtiStream);
    clear_eventfd(arti_stream.event_fd);
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

    let arti_stream = Box::from_raw(stream as *mut ArtiStream);

    // Mark as closed
    *arti_stream.closed.lock().unwrap() = true;

    // Close eventfd
    libc::close(arti_stream.event_fd);

    // Background task will terminate on next iteration
    // Stream is automatically cleaned up when dropped
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
    LAST_ERROR.with(|e| {
        let err = e.borrow();
        match &*err {
            Some(s) => {
                match CString::new(s.as_str()) {
                    Ok(cs) => cs.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            None => std::ptr::null_mut(),
        }
    })
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
    const VERSION: &[u8] = b"arti-vpp-ffi 0.1.0 (production)\0";
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

    #[test]
    fn test_eventfd() {
        let fd = create_eventfd().unwrap();
        signal_eventfd(fd);
        clear_eventfd(fd);
        unsafe { libc::close(fd); }
    }
}
