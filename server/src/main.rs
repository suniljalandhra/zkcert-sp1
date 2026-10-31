//! zkCert prover API.
//!
//! - `POST /prove` (multipart: `eml` file, `wallet`, `disclose`) -> 202 `{ jobId, preview }`
//! - `GET /prove/{id}` -> `{ status, error?, bundle? }`
//! - `GET /vkey`, `GET /keys`, `GET /health`
//!
//! Privacy: email bytes are never written to disk or logged. The upload is checked on the host
//! (same `verify` as the guest), then only the guest input is kept in memory until its proof is
//! done, and dropped. Logs contain job ids and states only.

use std::{
    collections::HashMap,
    net::SocketAddr,
    panic::AssertUnwindSafe,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::Address;
use anyhow::Result;
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::json;
use tokio::sync::mpsc::{self, error::TrySendError};
use tower_http::cors::CorsLayer;
use zkcert_lib::{
    keys::{PinnedKey, KEYS},
    verify::GuestInput,
};
use zkcert_script::{
    bundle::{Decoded, ProofBundle},
    discover::KeySource,
    inputs::prepare,
    keys::{self, KnownKey},
    prover::{pinned_vkey, program_vkey, ZkProver},
};

/// Completion emails are tens of KB; anything near this is not one.
const MAX_UPLOAD: usize = 1024 * 1024;
const QUEUE_CAPACITY: usize = 8;
const JOB_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum Job {
    Queued,
    Proving,
    Done { bundle: Box<ProofBundle> },
    Failed { error: String },
}

type ProveFn = Box<dyn Fn(&GuestInput) -> Result<ProofBundle> + Send>;

struct AppState {
    jobs: Mutex<HashMap<String, (Job, Instant)>>,
    /// False once prover setup has failed; uploads are then refused before any email is read.
    prover_ok: AtomicBool,
    queue: mpsc::Sender<(String, GuestInput)>,
    /// Key records for building guest inputs (config/dkim-keys.json).
    records: Vec<KnownKey>,
    /// The guest's key table, so a key the guest would reject is refused before proving.
    table: Vec<PinnedKey>,
    vkey: String,
}

type Shared = Arc<AppState>;

fn set_job(state: &AppState, id: &str, job: Job) {
    let mut jobs = state.jobs.lock().unwrap_or_else(|e| e.into_inner());
    // Only finished jobs expire; queued/proving ones are bounded by the queue capacity.
    jobs.retain(|_, (job, at)| matches!(job, Job::Queued | Job::Proving) || at.elapsed() < JOB_TTL);
    jobs.insert(id.to_string(), (job, Instant::now()));
}

/// One proof at a time on a dedicated thread: proving is CPU- and memory-heavy.
fn spawn_worker(
    state: Shared,
    mut rx: mpsc::Receiver<(String, GuestInput)>,
    make: impl FnOnce() -> Result<ProveFn> + Send + 'static,
) {
    std::thread::spawn(move || {
        let prove = match make() {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::error!("prover setup failed: {e:#}");
                state.prover_ok.store(false, Ordering::SeqCst);
                None
            }
        };
        while let Some((id, input)) = rx.blocking_recv() {
            let Some(prove) = &prove else {
                set_job(
                    &state,
                    &id,
                    Job::Failed {
                        error: "prover unavailable".into(),
                    },
                );
                continue;
            };
            set_job(&state, &id, Job::Proving);
            tracing::info!(job = %id, "proving");
            // A panicking prover must fail this job, not kill the worker for every later one.
            let job = match std::panic::catch_unwind(AssertUnwindSafe(|| prove(&input))) {
                Ok(Ok(bundle)) => Job::Done {
                    bundle: Box::new(bundle),
                },
                Ok(Err(e)) => Job::Failed {
                    error: format!("prover failed: {e}"),
                },
                Err(_) => Job::Failed {
                    error: "prover crashed".into(),
                },
            };
            drop(input);
            tracing::info!(job = %id, ok = matches!(job, Job::Done { .. }), "finished");
            set_job(&state, &id, job);
        }
    });
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

/// Keeps the multipart status (413 when the body limit is hit) instead of a generic 400.
fn upload_error(e: axum::extract::multipart::MultipartError) -> ApiError {
    let status = e.status();
    let msg = if status == StatusCode::PAYLOAD_TOO_LARGE {
        "file too large (limit 1 MB)".to_string()
    } else {
        "malformed upload".to_string()
    };
    ApiError(status, msg)
}

async fn health(State(s): State<Shared>) -> Json<serde_json::Value> {
    let prover = if s.prover_ok.load(Ordering::SeqCst) {
        "ok"
    } else {
        "unavailable"
    };
    Json(json!({ "status": "ok", "prover": prover, "version": env!("CARGO_PKG_VERSION") }))
}

fn unavailable(msg: &str) -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, msg.into())
}

async fn vkey(State(s): State<Shared>) -> Json<serde_json::Value> {
    Json(json!({ "vkey": s.vkey }))
}

/// The keys the guest accepts (its compiled table), with their validity windows.
async fn list_keys(State(s): State<Shared>) -> Json<serde_json::Value> {
    let keys: Vec<_> = s
        .table
        .iter()
        .map(|k| {
            json!({
                "platform": k.platform,
                "name": k.name,
                "keyHash": alloy_primitives::B256::from(k.key_hash),
                "validFrom": k.valid_from,
                "validTo": k.valid_to,
            })
        })
        .collect();
    Json(json!({ "keys": keys }))
}

async fn submit(
    State(s): State<Shared>,
    mut form: Multipart,
) -> Result<impl IntoResponse, ApiError> {
    // Reserve a queue slot before reading the email, so a busy or broken prover costs nothing.
    if !s.prover_ok.load(Ordering::SeqCst) {
        return Err(unavailable("prover unavailable (see server logs)"));
    }
    let slot = s.queue.try_reserve().map_err(|e| match e {
        TrySendError::Full(()) => unavailable("prover queue is full, try again later"),
        TrySendError::Closed(()) => unavailable("prover unavailable (see server logs)"),
    })?;
    let (mut eml, mut wallet, mut disclose) = (None, None, false);
    while let Some(field) = form.next_field().await.map_err(upload_error)? {
        match field.name() {
            Some("eml") => eml = Some(field.bytes().await.map_err(upload_error)?),
            Some("wallet") => {
                let text = field.text().await.map_err(|_| bad("bad wallet"))?;
                wallet = Some(
                    text.trim()
                        .parse::<Address>()
                        .map_err(|_| bad("wallet must be a 0x address"))?,
                );
            }
            Some("disclose") => {
                disclose = field.text().await.map_err(|_| bad("bad disclose"))? == "true"
            }
            _ => {}
        }
    }
    let eml = eml.ok_or_else(|| bad("missing eml file"))?;
    let wallet = wallet.ok_or_else(|| bad("missing wallet"))?;
    if wallet == Address::ZERO {
        return Err(bad("wallet must not be the zero address"));
    }
    // Only pinned key records, never DNS; the guest's own key table is checked by `prepare`.
    let source = KeySource::Pinned(
        s.records
            .iter()
            .map(|k| (k.name.clone(), k.record.clone()))
            .collect(),
    );
    let prepared = prepare(&eml, &source, &s.table, wallet.into_array(), disclose)
        .await
        .map_err(|e| bad(format!("{e:#}")))?;
    drop(eml);

    let id = uuid::Uuid::new_v4().to_string();
    set_job(&s, &id, Job::Queued);
    slot.send((id.clone(), prepared.input));
    tracing::info!(job = %id, "queued");
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "jobId": id, "preview": Decoded::from(&prepared.expected) })),
    ))
}

async fn status(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Job>, ApiError> {
    let jobs = s.jobs.lock().unwrap_or_else(|e| e.into_inner());
    jobs.get(&id)
        .map(|(job, _)| Json(job.clone()))
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "unknown job".into()))
}

fn app(state: Shared, cors_origin: &str) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(
            cors_origin
                .parse::<HeaderValue>()
                .expect("ZKCERT_CORS_ORIGIN must be an origin"),
        )
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);
    Router::new()
        .route("/health", get(health))
        .route("/vkey", get(vkey))
        .route("/keys", get(list_keys))
        .route("/prove", post(submit))
        .route("/prove/{id}", get(status))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
        .layer(cors)
        .with_state(state)
}

fn new_state(
    records: Vec<KnownKey>,
    table: Vec<PinnedKey>,
    vkey: String,
    make: impl FnOnce() -> Result<ProveFn> + Send + 'static,
) -> Shared {
    let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
    let state = Arc::new(AppState {
        jobs: Mutex::new(HashMap::new()),
        prover_ok: AtomicBool::new(true),
        queue: tx,
        records,
        table,
        vkey,
    });
    spawn_worker(state.clone(), rx, make);
    state
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Bind to localhost by default: uploads are personal email, so exposing the server must be
    // an explicit choice.
    let addr: SocketAddr = std::env::var("ZKCERT_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .expect("ZKCERT_SERVER_ADDR must be host:port");
    let origin =
        std::env::var("ZKCERT_CORS_ORIGIN").unwrap_or_else(|_| "http://localhost:3000".into());

    let vkey = tokio::task::spawn_blocking(program_vkey)
        .await
        .expect("vkey");
    // Proofs from a build whose vkey differs from the published pin would never verify.
    let pinned = pinned_vkey().expect("config/program.json");
    if vkey != pinned {
        panic!("program vkey {vkey} != pinned {pinned}: rebuild, or run `zkcert vkey --write`");
    }
    tracing::info!(%vkey, prover = %std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into()), "program loaded");
    let state = new_state(keys::allowlist(), KEYS.to_vec(), vkey, || {
        let prover = ZkProver::from_env()?;
        Ok(Box::new(move |input: &GuestInput| prover.prove(input)) as ProveFn)
    });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    tracing::info!("zkcert-server listening on http://{addr} (CORS origin {origin})");
    axum::serve(listener, app(state, &origin))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await
        .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolType;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use zkcert_lib::{
        verify::{keccak, verify_with},
        PublicValues,
    };
    use zkcert_script::{discover::key_info, synth};

    const WALLET: &str = "0x1234567890123456789012345678901234567890";

    /// A test key table entry: platform Udemy, no time window.
    fn pinned(der: &[u8]) -> PinnedKey {
        PinnedKey {
            name: "test",
            platform: 2,
            key_hash: keccak(&[der]),
            valid_from: 0,
            valid_to: u64::MAX,
        }
    }

    /// A server whose records and key table hold one throwaway key, with a fake prover that
    /// returns a mock bundle of the values the guest would commit.
    fn mock_prover() -> Result<ProveFn> {
        Ok(Box::new(|input: &GuestInput| {
            let v = verify_with(input, &[pinned(&input.public_key_der)])?;
            ProofBundle::new("mock", "0xvkey".into(), &[], &PublicValues::abi_encode(&v))
        }) as ProveFn)
    }

    fn test_app() -> (Router, Vec<u8>) {
        test_app_with(mock_prover)
    }

    fn test_app_with(make: impl FnOnce() -> Result<ProveFn> + Send + 'static) -> (Router, Vec<u8>) {
        test_app_table(make, true)
    }

    fn test_app_table(
        make: impl FnOnce() -> Result<ProveFn> + Send + 'static,
        key_in_table: bool,
    ) -> (Router, Vec<u8>) {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let mail = synth::udemy();
        let record = synth::record(&key);
        let known = KnownKey {
            platform: 2,
            name: synth::key_name(&mail),
            key_hash: key_info(&record).unwrap().der_keccak,
            record,
        };
        let der = zkcert_script::inputs::key_der(&known.record).unwrap();
        let table = if key_in_table {
            vec![pinned(&der)]
        } else {
            vec![]
        };
        let state = new_state(vec![known], table, "0xvkey".into(), make);
        (
            app(state, "http://localhost:3000"),
            synth::sign(&mail, &key),
        )
    }

    fn multipart(eml: &[u8], wallet: &str) -> Request<Body> {
        let b = "XBOUNDARYX";
        let mut body = Vec::new();
        body.extend(
            format!(
                "--{b}\r\nContent-Disposition: form-data; name=\"eml\"; filename=\"m.eml\"\r\n\r\n"
            )
            .bytes(),
        );
        body.extend(eml);
        body.extend(
            format!(
                "\r\n--{b}\r\nContent-Disposition: form-data; name=\"wallet\"\r\n\r\n{wallet}\r\n"
            )
            .bytes(),
        );
        body.extend(format!("--{b}\r\nContent-Disposition: form-data; name=\"disclose\"\r\n\r\ntrue\r\n--{b}--\r\n").bytes());
        Request::post("/prove")
            .header("content-type", format!("multipart/form-data; boundary={b}"))
            .body(Body::from(body))
            .unwrap()
    }

    async fn call(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let (app, _) = test_app();
        let (status, body) = call(&app, Request::get("/health").body(Body::empty()).unwrap()).await;
        assert_eq!(
            (status, body["status"].as_str()),
            (StatusCode::OK, Some("ok"))
        );
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let (app, _) = test_app();
        let (status, _) = call(&app, Request::get("/nope").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Submits the email and polls until the job leaves queued/proving.
    async fn run_job(app: &Router, eml: &[u8]) -> serde_json::Value {
        let (status, body) = call(app, multipart(eml, WALLET)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id = body["jobId"].as_str().unwrap().to_string();
        for _ in 0..200 {
            let (_, job) = call(
                app,
                Request::get(format!("/prove/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            if job["status"] == "done" || job["status"] == "failed" {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("job did not finish");
    }

    #[tokio::test]
    async fn prover_error_fails_the_job() {
        let (app, eml) =
            test_app_with(|| Ok(Box::new(|_: &GuestInput| anyhow::bail!("boom")) as ProveFn));
        let job = run_job(&app, &eml).await;
        assert_eq!(
            (job["status"].as_str(), job["error"].as_str()),
            (Some("failed"), Some("prover failed: boom"))
        );
    }

    #[tokio::test]
    async fn prover_panic_fails_the_job_and_worker_survives() {
        let (app, eml) = test_app_with(|| {
            Ok(Box::new(|_: &GuestInput| -> Result<ProofBundle> { panic!("crash") }) as ProveFn)
        });
        for _ in 0..2 {
            let job = run_job(&app, &eml).await;
            assert_eq!(job["error"], "prover crashed");
        }
    }

    #[tokio::test]
    async fn failed_prover_setup_refuses_uploads() {
        let (app, eml) = test_app_with(|| anyhow::bail!("no network key"));
        let mut last = StatusCode::OK;
        for _ in 0..100 {
            let (_, h) = call(&app, Request::get("/health").body(Body::empty()).unwrap()).await;
            if h["prover"] == "unavailable" {
                last = call(&app, multipart(&eml, WALLET)).await.0;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(last, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn queue_full_is_503() {
        // A prover that blocks: 1 job proving + QUEUE_CAPACITY queued, then the next is refused.
        let (app, eml) = test_app_with(|| {
            Ok(Box::new(|_: &GuestInput| -> Result<ProofBundle> {
                std::thread::sleep(Duration::from_secs(30));
                anyhow::bail!("slow")
            }) as ProveFn)
        });
        let mut statuses = Vec::new();
        for _ in 0..QUEUE_CAPACITY + 2 {
            statuses.push(call(&app, multipart(&eml, WALLET)).await.0);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(statuses.last(), Some(&StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(
            statuses
                .iter()
                .filter(|s| **s == StatusCode::ACCEPTED)
                .count(),
            QUEUE_CAPACITY + 1
        );
    }

    #[tokio::test]
    async fn missing_fields_are_400() {
        let (app, eml) = test_app();
        let b = "B";
        let only_wallet = format!("--{b}\r\nContent-Disposition: form-data; name=\"wallet\"\r\n\r\n{WALLET}\r\n--{b}--\r\n");
        let req = |body: String| {
            Request::post("/prove")
                .header("content-type", format!("multipart/form-data; boundary={b}"))
                .body(Body::from(body))
                .unwrap()
        };
        let (status, body) = call(&app, req(only_wallet)).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("missing eml file"))
        );
        let mut only_eml = format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"eml\"; filename=\"m.eml\"\r\n\r\n"
        )
        .into_bytes();
        only_eml.extend(&eml);
        only_eml.extend(format!("\r\n--{b}--\r\n").bytes());
        let (status, body) = call(&app, req(String::from_utf8(only_eml).unwrap())).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("missing wallet"))
        );
        let (status, _) = call(&app, req("garbage without boundaries".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn prove_flow_completes() {
        let (app, eml) = test_app();
        let (status, body) = call(&app, multipart(&eml, WALLET)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["preview"]["courseName"], "Tally With Tax");
        let id = body["jobId"].as_str().unwrap().to_string();
        for _ in 0..100 {
            let (_, job) = call(
                &app,
                Request::get(format!("/prove/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            if job["status"] == "done" {
                assert_eq!(job["bundle"]["decoded"]["wallet"], WALLET);
                return;
            }
            assert_ne!(job["status"], "failed", "{job}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("job did not finish");
    }

    #[tokio::test]
    async fn rejects_tampered_email() {
        let (app, eml) = test_app();
        let tampered = String::from_utf8(eml)
            .unwrap()
            .replace("Tally With Tax", "Harvard MBA");
        let (status, body) = call(&app, multipart(tampered.as_bytes(), WALLET)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("headers were modified"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn rejects_key_without_record() {
        let (app, _) = test_app();
        let other = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let (status, _) = call(
            &app,
            multipart(&synth::sign(&synth::udemy(), &other), WALLET),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_key_missing_from_guest_table() {
        // The host has the key record, but the guest's table does not list the key.
        let (app, eml) = test_app_table(mock_prover, false);
        let (status, body) = call(&app, multipart(&eml, WALLET)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap().contains("key table"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn rejects_bad_wallet() {
        let (app, eml) = test_app();
        assert_eq!(
            call(&app, multipart(&eml, "not-an-address")).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&app, multipart(&eml, &format!("{}", Address::ZERO)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn rejects_oversized_upload() {
        let (app, _) = test_app();
        let big = vec![b'a'; MAX_UPLOAD + 1];
        assert_eq!(
            call(&app, multipart(&big, WALLET)).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn unknown_job_is_404() {
        let (app, _) = test_app();
        let (status, _) = call(
            &app,
            Request::get("/prove/nope").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn exposes_vkey_and_keys() {
        let (app, _) = test_app();
        let (_, v) = call(&app, Request::get("/vkey").body(Body::empty()).unwrap()).await;
        assert_eq!(v["vkey"], "0xvkey");
        let (_, k) = call(&app, Request::get("/keys").body(Body::empty()).unwrap()).await;
        assert_eq!(k["keys"][0]["platform"], 2);
    }
}
