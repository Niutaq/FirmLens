use axum::{
    body::Body,
    extract::{Path as AxumPath, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use firmlens_core::{
    list_rules, scan_path, Finding, IngestionLimits, IngestionOutcome, InputKind, ScanLimits,
    ScanOptions, ScanReport, SummaryCounts, RULESET_VERSION, SCANNER_VERSION, SCHEMA_VERSION,
};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    io::Write,
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::Builder;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

pub const DEFAULT_PORT: u16 = 8787;
pub const MAX_ADMITTED_JOBS: usize = 4;
pub const MAX_ACTIVE_WORKERS: usize = 2;
pub const MAX_RETAINED_SCANS: usize = 8;
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub max_admitted_jobs: usize,
    pub max_active_workers: usize,
    pub max_retained_scans: usize,
    pub max_upload_bytes: u64,
    pub scan_limits: ScanLimits,
    pub ingestion_limits: IngestionLimits,
}

impl Default for ApiConfig {
    fn default() -> Self {
        let scan_limits = ScanLimits {
            max_file_bytes: 128 * 1024 * 1024, // 128 MiB per firmware image/file
            max_total_bytes: 256 * 1024 * 1024, // 256 MiB total read
            ..ScanLimits::default()
        };

        let ingestion_limits = IngestionLimits {
            max_input_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            max_expanded_bytes: 512 * 1024 * 1024, // 512 MiB expanded stream
            max_member_bytes: 128 * 1024 * 1024,   // 128 MiB per archive member
            ..IngestionLimits::default()
        };

        Self {
            max_admitted_jobs: MAX_ADMITTED_JOBS,
            max_active_workers: MAX_ACTIVE_WORKERS,
            max_retained_scans: MAX_RETAINED_SCANS,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            scan_limits,
            ingestion_limits,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredScan {
    pub id: String,
    pub filename: String,
    pub created_unix_ms: u64,
    pub report: ScanReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanListItem {
    pub id: String,
    pub filename: String,
    pub created_unix_ms: u64,
    pub partial: bool,
    pub ingestion_outcome: IngestionOutcome,
    pub files_scanned: usize,
    pub bytes_read: u64,
    pub summary: SummaryCounts,
}

impl From<&StoredScan> for ScanListItem {
    fn from(s: &StoredScan) -> Self {
        Self {
            id: s.id.clone(),
            filename: s.filename.clone(),
            created_unix_ms: s.created_unix_ms,
            partial: s.report.partial,
            ingestion_outcome: s.report.ingestion.outcome,
            files_scanned: s.report.metadata.files_scanned,
            bytes_read: s.report.metadata.bytes_read,
            summary: s.report.summary.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub scanner_version: String,
    pub schema_version: String,
    pub ruleset_version: String,
    pub retained_scans: usize,
    pub limits: ApiLimitsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiLimitsSummary {
    pub max_admitted_jobs: usize,
    pub max_active_workers: usize,
    pub max_retained_scans: usize,
    pub max_upload_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResponse {
    pub base_id: String,
    pub base_filename: String,
    pub target_id: String,
    pub target_filename: String,
    pub base_partial: bool,
    pub target_partial: bool,
    pub coverage_warning: Option<String>,
    pub delta: DiffDeltaCounts,
    pub resolved_findings: Vec<Finding>,
    pub new_findings: Vec<Finding>,
    pub unchanged_findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffDeltaCounts {
    pub actionable_delta: i64,
    pub review_delta: i64,
    pub hints_delta: i64,
    pub suppressed_delta: i64,
    pub skipped_delta: i64,
    pub files_scanned_delta: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub config: ApiConfig,
    admission_sem: Arc<Semaphore>,
    worker_sem: Arc<Semaphore>,
    scans: Arc<Mutex<VecDeque<StoredScan>>>,
}

impl AppState {
    pub fn new(config: ApiConfig) -> Self {
        Self {
            admission_sem: Arc::new(Semaphore::new(config.max_admitted_jobs)),
            worker_sem: Arc::new(Semaphore::new(config.max_active_workers)),
            scans: Arc::new(Mutex::new(VecDeque::with_capacity(
                config.max_retained_scans,
            ))),
            config,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
    code: String,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ApiErrorBody {
            error: self.message,
            code: self.code.to_string(),
        });
        (self.status, body).into_response()
    }
}

/// Validate that a bind IP is strictly a loopback address (`127.0.0.1` or `::1`).
pub fn ensure_loopback_ip(ip: IpAddr) -> Result<(), String> {
    if ip.is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "refusing to bind firmlens-api to non-loopback address {ip}; only 127.0.0.1 or ::1 is permitted"
        ))
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(get_health))
        .route("/api/rules", get(get_rules))
        .route("/api/scans", get(list_scans).post(upload_and_scan))
        .route("/api/scans/{id}", get(get_scan).delete(delete_scan))
        .route("/api/scans/{id}/report", get(export_scan_report))
        .route("/api/diff", get(get_diff))
        .layer(middleware::from_fn(loopback_security_middleware))
        .with_state(state)
}

fn is_valid_loopback_host(host_header: &str) -> bool {
    let trimmed = host_header.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    let host_part = if let Some(rest) = trimmed.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        trimmed.split(':').next().unwrap_or("")
    };
    matches!(host_part, "127.0.0.1" | "localhost" | "::1")
}

fn is_valid_loopback_origin(origin: &str) -> bool {
    let lower = origin.trim().to_ascii_lowercase();
    for prefix in [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "https://127.0.0.1",
        "https://localhost",
        "https://[::1]",
    ] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            if rest.is_empty()
                || (rest.starts_with(':') && rest[1..].chars().all(|c| c.is_ascii_digit()))
            {
                return true;
            }
        }
    }
    false
}

async fn loopback_security_middleware(req: Request, next: Next) -> Response {
    let headers = req.headers();

    // 1. Validate Host header (DNS rebinding protection)
    if let Some(host_val) = headers.get(header::HOST) {
        let Ok(host_str) = host_val.to_str() else {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid_host_header",
                "Host header is not valid ASCII",
            )
            .into_response();
        };
        if !is_valid_loopback_host(host_str) {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "untrusted_host",
                "Requests must target a loopback Host (127.0.0.1 or localhost)",
            )
            .into_response();
        }
    }

    // 2. Validate Origin header when present (browser CSRF / cross-origin protection)
    let mut allowed_origin: Option<HeaderValue> = None;
    if let Some(origin_val) = headers.get(header::ORIGIN) {
        let Ok(origin_str) = origin_val.to_str() else {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid_origin_header",
                "Origin header is not valid ASCII",
            )
            .into_response();
        };
        if !is_valid_loopback_origin(origin_str) {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "untrusted_origin",
                "Cross-origin requests from non-loopback origins are forbidden",
            )
            .into_response();
        }
        allowed_origin = HeaderValue::from_str(origin_str).ok();
    }

    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        if let Some(origin) = allowed_origin {
            let h = resp.headers_mut();
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            h.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
            );
            h.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("Content-Type, X-Filename"),
            );
        }
        return resp;
    }

    let mut resp = next.run(req).await;
    if let Some(origin) = allowed_origin {
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        h.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    resp
}

async fn get_health(State(state): State<AppState>) -> Json<HealthResponse> {
    let retained_scans = state.scans.lock().await.len();
    Json(HealthResponse {
        status: "ok".to_string(),
        scanner_version: SCANNER_VERSION.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        ruleset_version: RULESET_VERSION.to_string(),
        retained_scans,
        limits: ApiLimitsSummary {
            max_admitted_jobs: state.config.max_admitted_jobs,
            max_active_workers: state.config.max_active_workers,
            max_retained_scans: state.config.max_retained_scans,
            max_upload_bytes: state.config.max_upload_bytes,
        },
    })
}

async fn get_rules() -> Json<serde_json::Value> {
    Json(serde_json::to_value(list_rules()).unwrap_or_default())
}

async fn list_scans(State(state): State<AppState>) -> Json<Vec<ScanListItem>> {
    let guard = state.scans.lock().await;
    // Return newest first for UI convenience
    let items: Vec<ScanListItem> = guard.iter().rev().map(ScanListItem::from).collect();
    Json(items)
}

async fn get_scan(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<StoredScan>, ApiError> {
    let guard = state.scans.lock().await;
    let found = guard.iter().find(|s| s.id == id).cloned().ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, "scan_not_found", "Scan ID not found")
    })?;
    Ok(Json(found))
}

async fn delete_scan(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, ApiError> {
    let mut guard = state.scans.lock().await;
    let before = guard.len();
    guard.retain(|s| s.id != id);
    if guard.len() == before {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "scan_not_found",
            "Scan ID not found",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn export_scan_report(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let guard = state.scans.lock().await;
    let found = guard.iter().find(|s| s.id == id).cloned().ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, "scan_not_found", "Scan ID not found")
    })?;
    drop(guard);

    let mut json_bytes = serde_json::to_vec_pretty(&found.report).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialization_error",
            "Failed to serialize report",
        )
    })?;
    json_bytes.push(b'\n');

    let safe_stem = found
        .filename
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".tgz")
        .trim_end_matches(".tar")
        .trim_end_matches(".zip")
        .trim_end_matches(".bin")
        .trim_end_matches(".img")
        .trim_end_matches(".fw")
        .trim_end_matches(".chk")
        .trim_end_matches(".pat")
        .trim_end_matches(".rom")
        .trim_end_matches(".ubi")
        .trim_end_matches(".dat");
    let attachment = format!("attachment; filename=\"{safe_stem}.firmlens.json\"");

    let mut resp = (StatusCode::OK, json_bytes).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    if let Ok(val) = HeaderValue::from_str(&attachment) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, val);
    }
    Ok(resp)
}

#[derive(Debug, Default, Deserialize)]
struct UploadQuery {
    filename: Option<String>,
    path: Option<String>,
    file_path: Option<String>,
}

fn sanitize_archive_filename(raw: &str) -> Result<(String, &'static str), ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_filename",
            "Archive filename is required",
        ));
    }
    // Extract basename only (never trust client directory components)
    let base_raw = trimmed.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if base_raw.is_empty() || base_raw.starts_with('.') {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_filename",
            "Invalid archive filename",
        ));
    }

    // Replace vendor filename punctuation (e.g. brackets `[20260603]`, parentheses, spaces) with `_`
    let base: String = base_raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();

    let lower = base.to_ascii_lowercase();
    const ALLOWED_SUFFIXES: &[&str] = &[
        ".tar.gz", ".tgz", ".tar", ".zip", ".bin", ".img", ".fw", ".chk", ".pat", ".rom", ".ubi",
        ".dat", ".conf", ".cfg", ".ini", ".env", ".pem", ".key", ".json", ".yaml", ".yml",
    ];
    let Some(&suffix) = ALLOWED_SUFFIXES.iter().find(|&&s| lower.ends_with(s)) else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_archive_extension",
            "Web uploads accept .tar, .tar.gz, .tgz, .zip, .bin, .img, .fw, .chk, .pat, .rom, .ubi, .dat, or config/key files",
        ));
    };

    Ok((base, suffix))
}

async fn upload_and_scan(
    State(state): State<AppState>,
    Query(query): Query<UploadQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<StoredScan>), ApiError> {
    // Never accept server filesystem paths from HTTP clients
    if query.path.is_some() || query.file_path.is_some() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "server_filesystem_path_rejected",
            "Server filesystem paths are never accepted from HTTP clients; upload an archive stream instead.",
        ));
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if content_type.contains("application/json") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "server_filesystem_path_rejected",
            "JSON path scan requests are forbidden; upload a bounded TAR/TAR.GZ archive stream.",
        ));
    }

    // 1. Bounded admission check (at most 4 concurrent uploads/jobs)
    let _admission_permit = state
        .admission_sem
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "admission_limit_reached",
                "Maximum concurrent upload/scan jobs (4) reached; retry shortly.",
            )
        })?;

    // Check Content-Length header early if present
    if let Some(cl) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if cl > state.config.max_upload_bytes {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload_limit_exceeded",
                format!(
                    "Upload size ({cl} bytes) exceeds maximum allowed ({} bytes)",
                    state.config.max_upload_bytes
                ),
            ));
        }
    }

    let raw_filename = query.filename.or_else(|| {
        headers
            .get("x-filename")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });

    // 2. Stream request body chunks with strict byte limit
    let mut stream = body.into_data_stream();
    let mut total_received: u64 = 0;
    let max_bytes = state.config.max_upload_bytes;

    // If multipart/form-data is used, collect bounded bytes and extract the file payload + filename;
    // otherwise stream directly to temporary file.
    let is_multipart = content_type.starts_with("multipart/form-data");

    let (sanitized_name, temp_archive) = if is_multipart {
        let mut raw_body = Vec::new();
        while let Some(chunk_res) = stream.frame().await {
            let frame = chunk_res.map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "upload_stream_error",
                    "Failed to read upload stream frame",
                )
            })?;
            if let Ok(data) = frame.into_data() {
                total_received = total_received.saturating_add(data.len() as u64);
                if total_received > max_bytes {
                    return Err(ApiError::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "upload_limit_exceeded",
                        format!("Upload stream exceeded limit of {max_bytes} bytes"),
                    ));
                }
                raw_body.extend_from_slice(&data);
            }
        }
        let (mp_filename, payload) =
            extract_multipart_file(&content_type, &raw_body, raw_filename.as_deref())?;
        let (clean_name, suffix) = sanitize_archive_filename(&mp_filename)?;
        let mut tmp = Builder::new()
            .prefix("firmlens-upload-")
            .suffix(suffix)
            .tempfile()
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "staging_error",
                    "Failed to allocate temporary upload file",
                )
            })?;
        tmp.write_all(payload).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "staging_write_error",
                "Failed to write uploaded archive to temporary storage",
            )
        })?;
        tmp.flush().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "staging_flush_error",
                "Failed to flush uploaded archive",
            )
        })?;
        (clean_name, tmp)
    } else {
        let candidate_name = raw_filename.ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "missing_filename",
                "Provide archive filename via ?filename=<name>.tar(.gz) or X-Filename header",
            )
        })?;
        let (clean_name, suffix) = sanitize_archive_filename(&candidate_name)?;
        let mut tmp = Builder::new()
            .prefix("firmlens-upload-")
            .suffix(suffix)
            .tempfile()
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "staging_error",
                    "Failed to allocate temporary upload file",
                )
            })?;

        while let Some(chunk_res) = stream.frame().await {
            let frame = chunk_res.map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "upload_stream_error",
                    "Failed to read upload stream frame",
                )
            })?;
            if let Ok(data) = frame.into_data() {
                total_received = total_received.saturating_add(data.len() as u64);
                if total_received > max_bytes {
                    return Err(ApiError::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "upload_limit_exceeded",
                        format!("Upload stream exceeded limit of {max_bytes} bytes"),
                    ));
                }
                tmp.write_all(&data).map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "staging_write_error",
                        "Failed to write uploaded chunk",
                    )
                })?;
            }
        }
        if total_received == 0 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "empty_upload",
                "Uploaded archive body is empty",
            ));
        }
        tmp.flush().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "staging_flush_error",
                "Failed to flush uploaded archive",
            )
        })?;
        (clean_name, tmp)
    };

    // 3. Acquire bounded analysis worker permit (at most 2 concurrent analyses)
    let _worker_permit = state
        .worker_sem
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "worker_pool_closed",
                "Analysis worker pool unavailable",
            )
        })?;

    let mut ingestion_limits = state.config.ingestion_limits.clone();
    ingestion_limits.max_input_bytes = ingestion_limits
        .max_input_bytes
        .min(state.config.max_upload_bytes);

    // Give isolated Binwalk unpack enough wall-clock budget without blocking the Tokio runtime
    // (analysis runs on spawn_blocking below).
    ingestion_limits.ingestion_timeout_ms = ingestion_limits.ingestion_timeout_ms.max(180_000);

    let scan_opts = ScanOptions {
        scan_limits: state.config.scan_limits.clone(),
        ingestion_limits,
        excluded_output_path: None,
        enable_binwalk: true,
        enable_binwalk_extract: true,
        binwalk_image: None,
        // Fallback when Docker/Binwalk image is unavailable: bounded raw binary string scan.
        scan_binary_image_payload: true,
    };

    let display_name = sanitized_name.clone();
    // Two-stage unpack+scan is CPU/IO heavy; never run it on the async reactor thread.
    let scan_result = tokio::task::spawn_blocking(move || {
        let path: &Path = temp_archive.path();
        let res = scan_path(path, &scan_opts);
        // Explicitly close temporary uploaded archive file
        let _ = temp_archive.close();
        res
    })
    .await
    .map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "worker_join_error",
            "Analysis worker task failed unexpectedly",
        )
    })?;

    let mut report = scan_result.map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "scan_failed",
            format!("Failed to analyze uploaded archive: {e}"),
        )
    })?;

    // Never leak server temporary paths in metadata.root. For extracted firmware images,
    // keep relative paths inside the unpacked tree (rewrite only the staged `firmware.bin`
    // prefix to the uploaded display name). Collapse to the upload name only for raw
    // binary-payload scans that never produced a filesystem tree.
    report.metadata.root = display_name.clone();
    if report.ingestion.input_kind == InputKind::BinaryImage {
        if report.ingestion.outcome == IngestionOutcome::ImageExtracted {
            let rewrite = |path: &str| -> String {
                if let Some(rest) = path.strip_prefix("firmware.bin") {
                    format!("{display_name}{rest}")
                } else if path == "firmware.bin" {
                    display_name.clone()
                } else {
                    path.to_string()
                }
            };
            for f in &mut report.findings {
                f.file_path = rewrite(&f.file_path);
            }
            for s in &mut report.suppressed {
                s.file_path = rewrite(&s.file_path);
            }
            for inv in &mut report.inventory {
                inv.path = rewrite(&inv.path);
            }
            for sk in &mut report.skipped_files {
                sk.path = rewrite(&sk.path);
            }
            for err in &mut report.errors {
                if err.path != "<staging_workspace>" && err.path != "<unknown>" {
                    err.path = rewrite(&err.path);
                }
            }
        } else {
            for f in &mut report.findings {
                f.file_path = display_name.clone();
            }
            for s in &mut report.suppressed {
                s.file_path = display_name.clone();
            }
            for inv in &mut report.inventory {
                inv.path = display_name.clone();
            }
            for sk in &mut report.skipped_files {
                sk.path = display_name.clone();
            }
        }
    }

    let created_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let stored = StoredScan {
        id: Uuid::new_v4().to_string(),
        filename: display_name,
        created_unix_ms,
        report,
    };

    // 4. Retain at most 8 scans in memory (FIFO eviction)
    {
        let mut guard = state.scans.lock().await;
        while guard.len() >= state.config.max_retained_scans {
            guard.pop_front();
        }
        guard.push_back(stored.clone());
    }

    Ok((StatusCode::CREATED, Json(stored)))
}

fn extract_multipart_file<'a>(
    content_type: &str,
    raw_body: &'a [u8],
    fallback_filename: Option<&str>,
) -> Result<(String, &'a [u8]), ApiError> {
    let boundary = content_type
        .split(';')
        .find_map(|part| {
            let trimmed = part.trim();
            trimmed
                .strip_prefix("boundary=")
                .map(|b| b.trim_matches('"'))
        })
        .filter(|b| !b.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_multipart",
                "Missing multipart boundary",
            )
        })?;

    let delimiter = format!("--{boundary}");
    let delim_bytes = delimiter.as_bytes();

    // Locate first part header after `--<boundary>\r\n`
    let Some(first_pos) = find_subslice(raw_body, delim_bytes) else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_multipart",
            "Multipart boundary not found in body",
        ));
    };

    let after_delim = &raw_body[first_pos + delim_bytes.len()..];
    let after_line = after_delim
        .strip_prefix(b"\r\n")
        .or_else(|| after_delim.strip_prefix(b"\n"))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_multipart",
                "Malformed multipart preamble",
            )
        })?;

    let (headers_bytes, rest) = if let Some(idx) = find_subslice(after_line, b"\r\n\r\n") {
        (&after_line[..idx], &after_line[idx + 4..])
    } else if let Some(idx) = find_subslice(after_line, b"\n\n") {
        (&after_line[..idx], &after_line[idx + 2..])
    } else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_multipart",
            "Multipart headers terminator not found",
        ));
    };

    let headers_str = String::from_utf8_lossy(headers_bytes);
    let parsed_filename = headers_str
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-disposition:") {
                line.split(';').find_map(|seg| {
                    let s = seg.trim();
                    if s.to_ascii_lowercase().starts_with("filename=") {
                        Some(s[9..].trim_matches('"').to_string())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
        .or_else(|| fallback_filename.map(|s| s.to_string()))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "missing_filename",
                "Multipart upload missing filename attribute",
            )
        })?;

    let end_pos = find_subslice(rest, delim_bytes).ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_multipart",
            "Closing multipart boundary not found",
        )
    })?;

    let mut payload = &rest[..end_pos];
    if let Some(stripped) = payload.strip_suffix(b"\r\n") {
        payload = stripped;
    } else if let Some(stripped) = payload.strip_suffix(b"\n") {
        payload = stripped;
    }

    if payload.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty_upload",
            "Uploaded archive file part is empty",
        ));
    }

    Ok((parsed_filename, payload))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Debug, Deserialize)]
struct DiffQuery {
    base: String,
    target: String,
}

fn finding_identity_key(f: &Finding) -> (String, String, u64, String) {
    (
        f.file_path.clone(),
        f.rule_id.clone(),
        f.byte_offset,
        format!("{:?}:{:?}", f.kind, f.status),
    )
}

async fn get_diff(
    State(state): State<AppState>,
    Query(q): Query<DiffQuery>,
) -> Result<Json<DiffResponse>, ApiError> {
    let guard = state.scans.lock().await;
    let base = guard
        .iter()
        .find(|s| s.id == q.base)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "base_scan_not_found",
                "Base scan ID not found",
            )
        })?;
    let target = guard
        .iter()
        .find(|s| s.id == q.target)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "target_scan_not_found",
                "Target scan ID not found",
            )
        })?;
    drop(guard);

    let coverage_warning = if base.report.partial || target.report.partial {
        Some(
            "One or both reports have partial coverage (excluded files, errors, or unexpanded archives). Fewer findings in a partial scan is not proof of improved security."
                .to_string(),
        )
    } else {
        None
    };

    let mut base_map: BTreeMap<(String, String, u64, String), Finding> = BTreeMap::new();
    for f in &base.report.findings {
        base_map.insert(finding_identity_key(f), f.clone());
    }

    let mut target_map: BTreeMap<(String, String, u64, String), Finding> = BTreeMap::new();
    for f in &target.report.findings {
        target_map.insert(finding_identity_key(f), f.clone());
    }

    let mut resolved_findings = Vec::new();
    let mut unchanged_findings = Vec::new();
    for (k, f) in &base_map {
        if target_map.contains_key(k) {
            unchanged_findings.push(f.clone());
        } else {
            resolved_findings.push(f.clone());
        }
    }

    let mut new_findings = Vec::new();
    for (k, f) in &target_map {
        if !base_map.contains_key(k) {
            new_findings.push(f.clone());
        }
    }

    let delta = DiffDeltaCounts {
        actionable_delta: target.report.summary.actionable_findings as i64
            - base.report.summary.actionable_findings as i64,
        review_delta: target.report.summary.review_candidates as i64
            - base.report.summary.review_candidates as i64,
        hints_delta: target.report.summary.informational_hints as i64
            - base.report.summary.informational_hints as i64,
        suppressed_delta: target.report.summary.suppressed_candidates as i64
            - base.report.summary.suppressed_candidates as i64,
        skipped_delta: target.report.summary.skipped_entries as i64
            - base.report.summary.skipped_entries as i64,
        files_scanned_delta: target.report.metadata.files_scanned as i64
            - base.report.metadata.files_scanned as i64,
    };

    Ok(Json(DiffResponse {
        base_id: base.id,
        base_filename: base.filename,
        target_id: target.id,
        target_filename: target.filename,
        base_partial: base.report.partial,
        target_partial: target.report.partial,
        coverage_warning,
        delta,
        resolved_findings,
        new_findings,
        unchanged_findings,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tar::{Builder as TarBuilder, Header};
    use tower::ServiceExt;

    fn build_minimal_tar_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tar = TarBuilder::new(&mut buf);
            let data = b"password = \"SynthApiTestSecret99!\"\n";
            let mut header = Header::new_ustar();
            header.set_path("etc/device.conf").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, &data[..]).unwrap();
            tar.finish().unwrap();
        }
        buf
    }

    #[tokio::test]
    async fn rejects_non_loopback_bind_addresses() {
        assert!(ensure_loopback_ip("127.0.0.1".parse().unwrap()).is_ok());
        assert!(ensure_loopback_ip("::1".parse().unwrap()).is_ok());
        assert!(ensure_loopback_ip("0.0.0.0".parse().unwrap()).is_err());
        assert!(ensure_loopback_ip("192.168.1.10".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn enforces_host_and_origin_validation() {
        let app = build_router(AppState::new(ApiConfig::default()));

        // Untrusted Host -> 403
        let req_bad_host = Request::builder()
            .uri("/api/health")
            .header("Host", "evil.example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req_bad_host).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Untrusted Origin -> 403
        let req_bad_origin = Request::builder()
            .uri("/api/health")
            .header("Host", "127.0.0.1:8787")
            .header("Origin", "https://attacker.invalid")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req_bad_origin).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Valid loopback Host and Origin -> 200 OK
        let req_ok = Request::builder()
            .uri("/api/health")
            .header("Host", "127.0.0.1:8787")
            .header("Origin", "http://127.0.0.1:5173")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req_ok).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_server_filesystem_paths_from_http_clients() {
        let app = build_router(AppState::new(ApiConfig::default()));

        let req_query_path = Request::builder()
            .method(Method::POST)
            .uri("/api/scans?path=/etc/passwd")
            .header("Host", "127.0.0.1:8787")
            .body(Body::from("dummy"))
            .unwrap();
        let resp = app.clone().oneshot(req_query_path).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let req_json_path = Request::builder()
            .method(Method::POST)
            .uri("/api/scans")
            .header("Host", "127.0.0.1:8787")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"path":"fixtures/vulnerable"}"#))
            .unwrap();
        let resp = app.oneshot(req_json_path).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn enforces_upload_size_limit_and_retention_cap() {
        let cfg = ApiConfig {
            max_upload_bytes: 2048,
            max_retained_scans: 2,
            ..Default::default()
        };
        let app = build_router(AppState::new(cfg));

        // Oversized upload -> 413 Payload Too Large
        let big_payload = vec![b'A'; 4096];
        let req_big = Request::builder()
            .method(Method::POST)
            .uri("/api/scans?filename=oversized.tar")
            .header("Host", "127.0.0.1:8787")
            .body(Body::from(big_payload))
            .unwrap();
        let resp_big = app.clone().oneshot(req_big).await.unwrap();
        assert_eq!(resp_big.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Upload 3 valid small archives with retention cap = 2 -> only newest 2 retained
        let tar_bytes = build_minimal_tar_bytes();
        for i in 1..=3 {
            let req = Request::builder()
                .method(Method::POST)
                .uri(format!("/api/scans?filename=sample{i}.tar"))
                .header("Host", "127.0.0.1:8787")
                .body(Body::from(tar_bytes.clone()))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let list_req = Request::builder()
            .uri("/api/scans")
            .header("Host", "127.0.0.1:8787")
            .body(Body::empty())
            .unwrap();
        let list_resp = app.oneshot(list_req).await.unwrap();
        let body_bytes = list_resp.into_body().collect().await.unwrap().to_bytes();
        let items: Vec<ScanListItem> = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].filename, "sample3.tar");
        assert_eq!(items[1].filename, "sample2.tar");
    }
}
