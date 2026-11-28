mod api;
mod identity;
mod store;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value = "8080")]
        listen: String,
        #[arg(long)]
        password: Option<String>,
    },
    Serve {
        #[arg(long)]
        db: PathBuf,
    },
}
struct App {
    db: PathBuf,
    discovery: identity::Discovery,
    logins: Mutex<()>,
    workers: Arc<tokio::sync::Semaphore>,
}
type Shared = Arc<App>;

async fn api(
    State(app): State<Shared>,
    Path(op): Path<String>,
    headers: HeaderMap,
    Json(v): Json<Value>,
) -> Response {
    let credential = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let Ok(permit) = app.clone().workers.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        api::request(app, op, v, credential)
    })
    .await;
    let response = match result {
        Ok(Ok(v)) => (StatusCode::OK, Json(v)),
        Ok(Err(e)) => {
            let msg = e.to_string();
            let status = match msg.as_str() {
                "unauthorized" => StatusCode::UNAUTHORIZED,
                "forbidden" => StatusCode::FORBIDDEN,
                "not found" => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(json!({"error":format!("{e:#}")})))
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal server error"})),
        ),
    };
    ([(header::CACHE_CONTROL, "no-store")], response).into_response()
}
async fn public_file(app: Shared, key: String, srs: bool) -> Response {
    let result=tokio::task::spawn_blocking(move ||->Result<Option<Vec<u8>>>{
        let c=store::connection(&app.db)?;
        if srs {
            let Some(tag)=key.strip_suffix(".srs") else {return Ok(None)};
            return Ok(c.query_row("select bytes from blobs where tag=?",[tag],|r|r.get(0)).optional()?)
        }
        Ok(c.query_row("select c.output from links l join configs c on c.id=l.target and c.owner=l.owner where token=? and c.output is not null",[key],|r|r.get::<_,String>(0)).optional()?.map(String::into_bytes))
    }).await;
    match result {
        Ok(Ok(Some(bytes))) => {
            let (mime, cache) = if srs {
                (
                    "application/octet-stream",
                    "public, max-age=31536000, immutable",
                )
            } else {
                ("application/json", "no-store")
            };
            (
                [
                    (header::CONTENT_TYPE, mime),
                    (header::CACHE_CONTROL, cache),
                    (header::REFERRER_POLICY, "no-referrer"),
                ],
                bytes,
            )
                .into_response()
        }
        Ok(Ok(None)) => {
            ([(header::CACHE_CONTROL, "no-store")], StatusCode::NOT_FOUND).into_response()
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let db = match Cli::parse().cmd {
        Command::Init {
            db,
            listen,
            password,
        } => return store::init(&db, &listen, password),
        Command::Serve { db } => db,
    };
    let listen: String =
        store::connection(&db)?
            .query_row("select listen from settings where id=1", [], |r| r.get(0))?;
    let app=Router::new()
        .route("/",get(||async{([(header::CACHE_CONTROL,"no-store"),(header::REFERRER_POLICY,"no-referrer"),(header::CONTENT_SECURITY_POLICY,"default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")],Html(include_str!("index.html")))}))
        .route("/app.js",get(||async{([(header::CONTENT_TYPE,"application/javascript")],include_str!("app.js"))}))
        .route("/style.css",get(||async{([(header::CONTENT_TYPE,"text/css")],include_str!("style.css"))}))
        .route("/api/{op}",post(api))
        .route("/s/{key}",get(|State(a):State<Shared>,Path(k):Path<String>|public_file(a,k,false)))
        .route("/srs/{key}",get(|State(a):State<Shared>,Path(k):Path<String>|public_file(a,k,true)))
        .layer(DefaultBodyLimit::max(32*1024*1024)).with_state(Arc::new(App{db,discovery:Default::default(),logins:Mutex::new(()),workers:Arc::new(tokio::sync::Semaphore::new(16))}));
    #[cfg(unix)]
    if let Some(path) = listen.strip_prefix("unix:") {
        use std::os::unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::UnixStream,
        };
        // Serialize stale socket recovery with other instances listening on this path.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(format!("{path}.lock"))?;
        lock.try_lock()
            .context("another server owns the Unix listener")?;
        if let Ok(info) = std::fs::symlink_metadata(path) {
            anyhow::ensure!(
                info.file_type().is_socket(),
                "listener path is not a Unix socket"
            );
            match UnixStream::connect(path) {
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)?
                }
                _ => anyhow::bail!("Unix socket already in use"),
            }
        }
        let socket = tokio::net::UnixListener::bind(path).context("binding Unix socket")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        axum::serve(socket, app).await?;
        return Ok(());
    }
    axum::serve(tokio::net::TcpListener::bind(&listen).await?, app).await?;
    Ok(())
}
