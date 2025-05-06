use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Buf;
use futures_util::StreamExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::time::Instant;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Configuration struct with server settings
struct Config {
    upload_dir: PathBuf,
    port: u16,
    max_file_size: usize, // in bytes
    buffer_size: usize,   // size of buffer for file writing
}

// Custom error type to handle both hyper::Error and io::Error
enum UploadError {
    Io(io::Error),
    Hyper(hyper::Error),
    SizeLimitExceeded,
}

impl From<io::Error> for UploadError {
    fn from(err: io::Error) -> Self {
        UploadError::Io(err)
    }
}

impl From<hyper::Error> for UploadError {
    fn from(err: hyper::Error) -> Self {
        UploadError::Hyper(err)
    }
}

// Helper function to handle file upload using tokio's async file I/O
async fn save_file(
    mut body: Body,
    path: PathBuf,
    max_size: usize,
    buffer_size: usize,
) -> Result<usize, UploadError> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Use tokio's async file operations instead of std::fs
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .await?;

    let mut size = 0;
    let start = Instant::now();
    let mut bytes_per_second = 0.0;
    let mut last_log = Instant::now();

    // Process the stream in chunks with a fixed buffer size
    while let Some(chunk_result) = body.next().await {
        let chunk = chunk_result?;
        let chunk_size = chunk.len();
        size += chunk_size;

        // Check if file size exceeds maximum
        if size > max_size {
            // Close the file properly before returning error
            file.shutdown().await?;
            return Err(UploadError::SizeLimitExceeded);
        }

        // Write asynchronously
        file.write_all(&chunk).await?;

        // Log progress every second for large files
        let now = Instant::now();
        if now.duration_since(last_log).as_secs() >= 1 {
            let elapsed = now.duration_since(start).as_secs_f64();
            if elapsed > 0.0 {
                bytes_per_second = size as f64 / elapsed;
                println!(
                    "Upload progress: {:.2} MB, {:.2} MB/s",
                    size as f64 / 1_048_576.0,
                    bytes_per_second / 1_048_576.0
                );
            }
            last_log = now;
        }
    }

    // Ensure all data is flushed to disk
    file.sync_all().await?;

    // Log final statistics
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed > 0.0 {
        bytes_per_second = size as f64 / elapsed;
        println!(
            "Upload complete: {:.2} MB in {:.2}s ({:.2} MB/s)",
            size as f64 / 1_048_576.0,
            elapsed,
            bytes_per_second / 1_048_576.0
        );
    }

    Ok(size)
}

// Main request handler
async fn handle_request(
    req: Request<Body>,
    config: Arc<Config>,
) -> Result<Response<Body>, hyper::Error> {
    let method = req.method();
    let path = req.uri().path();

    // Sanitize the path to prevent directory traversal attacks
    let safe_path = path.trim_start_matches('/');
    /*
    if safe_path.contains("/") {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Path cannot contain '/'"))
            .unwrap());
    }*/

    let target_path = config.upload_dir.join(safe_path);

    match *method {
        Method::PUT | Method::POST => {
            println!("Receiving PUT request for: {}", safe_path);

            match save_file(
                req.into_body(),
                target_path.clone(),
                config.max_file_size,
                config.buffer_size,
            )
            .await
            {
                Ok(size) => {
                    let response = Response::builder()
                        .status(StatusCode::CREATED)
                        .body(Body::from(format!(
                            "File uploaded successfully. Size: {} bytes",
                            size
                        )))
                        .unwrap();
                    Ok(response)
                }
                Err(e) => {
                    // If the file was created but an error occurred, try to clean up
                    let _ = tokio::fs::remove_file(&target_path).await;

                    let (status, message) = match e {
                        UploadError::SizeLimitExceeded => (
                            StatusCode::PAYLOAD_TOO_LARGE,
                            format!(
                                "File size exceeds maximum allowed size of {} bytes",
                                config.max_file_size
                            ),
                        ),
                        UploadError::Io(err) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("I/O Error: {}", err),
                        ),
                        UploadError::Hyper(err) => {
                            (StatusCode::BAD_REQUEST, format!("Request Error: {}", err))
                        }
                    };

                    let response = Response::builder()
                        .status(status)
                        .body(Body::from(message))
                        .unwrap();
                    Ok(response)
                }
            }
        }
        // Add a HEAD method to check if a file exists
        Method::HEAD => {
            if target_path.exists() {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .unwrap())
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap())
            }
        }
        // For all other methods, return Method Not Allowed
        _ => {
            let response = Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Only PUT and HEAD methods are supported"))
                .unwrap();
            Ok(response)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Server configuration - adjust these values based on your hardware
    let config = Arc::new(Config {
        upload_dir: PathBuf::from("./uploads"),
        port: 3000,
        max_file_size: 10 * 1024 * 1024 * 1024, // 10 GB
        buffer_size: 64 * 1024,                 // 64 KB chunks - good balance for most hardware
    });

    // Create upload directory if it doesn't exist
    fs::create_dir_all(&config.upload_dir)?;

    println!("Starting high-performance file upload server...");
    println!("Upload directory: {}", config.upload_dir.display());
    println!(
        "Maximum file size: {} GB",
        config.max_file_size as f64 / 1_073_741_824.0
    );
    println!("Buffer size: {} KB", config.buffer_size / 1024);

    let addr = ([0, 0, 0, 0], config.port).into();
    let config_clone = config.clone();

    // Create a service with connection pool
    let make_svc = make_service_fn(move |_| {
        let config = config_clone.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| handle_request(req, config.clone()))) }
    });

    // Build the server with runtime configuration optimized for file uploads
    let server = Server::bind(&addr)
        .tcp_nodelay(true) // Disable Nagle's algorithm for better latency
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .serve(make_svc);

    println!("Server started on http://0.0.0.0:{}", config.port);

    // Run the server
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }

    Ok(())
}
