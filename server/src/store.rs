use anyhow::{Context, Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::{Rng, rngs::OsRng};
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const URLSAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
pub fn token(alphabet: &[u8]) -> String {
    let mut rng = OsRng;
    (0..43)
        .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
        .collect()
}
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn hash(p: &str) -> Result<String> {
    ensure!(!p.is_empty(), "password must be nonempty");
    Argon2::default()
        .hash_password(p.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))
}
pub fn verify(p: &str, h: &str) -> bool {
    PasswordHash::new(h).is_ok_and(|h| Argon2::default().verify_password(p.as_bytes(), &h).is_ok())
}
pub fn connection(path: &Path) -> Result<Connection> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    c.busy_timeout(Duration::from_secs(10))?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    Ok(c)
}
pub fn listener(s: &str) -> Result<String> {
    if let Some(path) = s.strip_prefix("unix:") {
        ensure!(
            cfg!(unix) && Path::new(path).is_absolute(),
            "expected unix:/absolute/path on Unix"
        );
        return Ok(s.to_string());
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(format!("127.0.0.1:{port}"));
    }
    Ok(s.parse::<SocketAddr>()
        .context("expected port, IP:port or unix:/path")?
        .to_string())
}
pub fn init(path: &Path, listen: &str, password: Option<String>) -> Result<()> {
    let bind = listener(listen)?;
    let generated = password.is_none();
    let password = password.unwrap_or_else(|| token(ALNUM));
    let encoded = hash(&password)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(
        options
            .open(path)
            .context("initialization requires a new database path")?,
    );
    let mut c = connection(path)?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    let tx = c.transaction()?;
    tx.execute_batch(include_str!("schema.sql"))?;
    tx.execute(
        "insert into settings(id,listen,password) values(1,?,?)",
        params![bind, encoded],
    )?;
    tx.commit()?;
    if generated {
        println!("{password}");
    }
    Ok(())
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Settings {
    pub public: String,
    pub issuer: String,
    pub client: String,
    pub audience: String,
    pub scope: String,
    pub imports: Vec<String>,
    pub epoch: i64,
}
impl Settings {
    pub fn read(c: &Connection) -> Result<Self> {
        let (mut settings,imports): (Self,String) = c.query_row("select public_url,issuer,client_id,audience,scope,imports,auth_epoch from settings where id=1",[],|r|
            Ok((Self{public:r.get(0)?,issuer:r.get(1)?,client:r.get(2)?,audience:r.get(3)?,scope:r.get(4)?,epoch:r.get(6)?,..Default::default()},r.get(5)?)))?;
        settings.imports = serde_json::from_str(&imports)?;
        Ok(settings)
    }
    pub fn json(&self) -> Value {
        json!({"public":self.public,"issuer":self.issuer,"client":self.client,"audience":self.audience,"scope":self.scope,"imports":self.imports})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn random_lengths_and_charset() {
        for alphabet in [ALNUM, URLSAFE] {
            let s = token(alphabet);
            assert_eq!(s.len(), 43);
            assert!(s.bytes().all(|b| alphabet.contains(&b)));
        }
        assert_eq!(URLSAFE.len(), 66);
    }
}
