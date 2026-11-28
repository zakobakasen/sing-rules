use crate::{
    App, identity,
    store::{self, Settings},
};
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::sync::Arc;

fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
fn id(v: &Value) -> Result<i64> {
    v["id"].as_i64().context("missing id")
}
fn rows(
    c: &Connection,
    sql: &str,
    args: impl rusqlite::Params,
    f: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
) -> Result<Vec<Value>> {
    Ok(c.prepare(sql)?
        .query_map(args, f)?
        .collect::<rusqlite::Result<_>>()?)
}

struct Identity {
    issuer: String,
    sub: String,
    local: bool,
}
struct User {
    owner: String,
    role: String,
}
impl Identity {
    fn user(&self, c: &Connection) -> Result<User> {
        if self.local {
            return Ok(User {
                owner: "bootstrap".into(),
                role: "admin".into(),
            });
        }
        let role = c
            .query_row(
                "select role from roles where issuer=? and sub=?",
                params![self.issuer, self.sub],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "guest".into());
        Ok(User {
            owner: json!([self.issuer, self.sub]).to_string(),
            role,
        })
    }
}
fn authenticate(app: &App, c: &Connection, s: &Settings, credential: &str) -> Result<Identity> {
    if let Some(secret) = credential.strip_prefix("Local ") {
        let exists: bool = c.query_row(
            "select exists(select 1 from sessions where digest=? and expires>unixepoch())",
            [blake3::hash(secret.as_bytes()).as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        ensure!(exists, "unauthorized");
        return Ok(Identity {
            issuer: String::new(),
            sub: String::new(),
            local: true,
        });
    }
    let at = credential.strip_prefix("Bearer ").context("unauthorized")?;
    let sub = app.discovery.verify(s, at)?;
    Ok(Identity {
        issuer: s.issuer.clone(),
        sub,
        local: false,
    })
}
fn own(c: &Connection, u: &User, table: &str, id: i64) -> Result<String> {
    let sql = match table {
        "configs" => "select owner from configs where id=?",
        "links" => "select owner from links where id=?",
        _ => unreachable!(),
    };
    let owner: String = c
        .query_row(sql, [id], |r| r.get(0))
        .optional()?
        .context("not found")?;
    ensure!(u.role == "admin" || u.owner == owner, "not found");
    Ok(owner)
}
fn admin(u: &User) -> Result<()> {
    ensure!(u.role == "admin", "forbidden");
    Ok(())
}

pub fn request(app: Arc<App>, op: String, v: Value, credential: String) -> Result<Value> {
    let mut c = store::connection(&app.db)?;
    let s = Settings::read(&c)?;
    match op.as_str() {
        "login" => {
            let _serial = app.logins.lock().unwrap();
            let stored: Option<String> =
                c.query_row("select password from settings", [], |r| r.get(0))?;
            let encoded = stored.context("unauthorized")?;
            ensure!(
                store::verify(string(&v, "password")?, &encoded),
                "unauthorized"
            );
            let token = store::token(store::ALNUM);
            c.execute("delete from sessions where expires<=unixepoch()", [])?;
            let n = c.execute(
                "insert into sessions select ?,unixepoch()+28800 from settings where password=?",
                params![
                    blake3::hash(token.as_bytes()).as_bytes().as_slice(),
                    encoded
                ],
            )?;
            ensure!(n == 1, "unauthorized");
            return Ok(json!({"token":token}));
        }
        "provider" => {
            if s.issuer.is_empty() {
                return Ok(Value::Null);
            }
            let m = app.discovery.metadata(&s)?;
            let auth = identity::endpoint(
                m["authorization_endpoint"]
                    .as_str()
                    .context("missing authorization endpoint")?,
            )?;
            let token = identity::endpoint(
                m["token_endpoint"].as_str().context("missing token endpoint")?,
            )?;
            return Ok(
                json!({"endpoint":auth.as_str(),"token_endpoint":token.as_str(),"fragment":m["response_modes_supported"].as_array().is_some_and(|modes| modes.iter().any(|mode| mode=="fragment")),"client":s.client,"audience":s.audience,"scope":s.scope,"issuer":s.issuer,"redirect":format!("{}/",s.public),"epoch":s.epoch}),
            );
        }
        _ => (),
    }
    let who = authenticate(&app, &c, &s, &credential)?;
    // Compile outside the SQLite write lock. Recheck identity, role and snapshot at publication.
    let publication = if op == "compile" {
        let u = who.user(&c)?;
        ensure!(u.role != "guest", "forbidden");
        own(&c, &u, "configs", id(&v)?)?;
        ensure!(!s.public.is_empty(), "configure the public URL first");
        let (sr, base, rev): (Option<String>, Option<String>, i64) = c.query_row(
            "select sr,base,revision from configs where id=?",
            [id(&v)?],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let p = sing_rules::publish(
            &sr.context("upload .sr first")?,
            &base.context("upload base JSON first")?,
            &s.public,
            s.imports.clone(),
        )?;
        Some((p, rev))
    } else {
        None
    };
    if publication.is_some() && !who.local {
        authenticate(&app, &c, &s, &credential)?;
    }
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    ensure!(Settings::read(&tx)? == s, "settings changed, retry");
    if who.local {
        authenticate(&app, &tx, &s, &credential)?;
    }
    let u = who.user(&tx)?;
    let value = match op.as_str() {
        "me" => {
            json!({"role":u.role,"owner":u.owner,"issuer":who.issuer,"sub":if who.local { Value::Null }else{json!(who.sub)}})
        }
        "logout" => {
            if let Some(secret) = credential.strip_prefix("Local ") {
                tx.execute(
                    "delete from sessions where digest=?",
                    [blake3::hash(secret.as_bytes()).as_bytes().as_slice()],
                )?;
            }
            Value::Null
        }
        _ if u.role == "guest" => bail!("forbidden"),
        "list" => {
            let args = params![u.role == "admin", u.owner];
            json!({"configs":rows(&tx,"select id,owner,note,sr is not null,base is not null,output is not null from configs where ? or owner=? order by id",args,|r|Ok(json!({"id":r.get::<_,i64>(0)?,"owner":r.get::<_,String>(1)?,"note":r.get::<_,String>(2)?,"sr":r.get::<_,bool>(3)?,"base":r.get::<_,bool>(4)?,"compiled":r.get::<_,bool>(5)?})))?,
                "links":rows(&tx,"select id,owner,note,token,target from links where ? or owner=? order by id",args,|r|Ok(json!({"id":r.get::<_,i64>(0)?,"owner":r.get::<_,String>(1)?,"note":r.get::<_,String>(2)?,"token":r.get::<_,String>(3)?,"target":r.get::<_,Option<i64>>(4)?})))?,"public":s.public})
        }
        "config-new" => {
            tx.execute(
                "insert into configs(owner,note) values (?,?)",
                params![u.owner, string(&v, "note")?],
            )?;
            json!(tx.last_insert_rowid())
        }
        "config-read" => {
            let key = id(&v)?;
            own(&tx, &u, "configs", key)?;
            tx.query_row(
                "select note,sr,base,revision from configs where id=?",
                [key],
                |r| {
                    Ok(json!({
                        "note":r.get::<_,String>(0)?, "sr":r.get::<_,Option<String>>(1)?,
                        "base":r.get::<_,Option<String>>(2)?, "revision":r.get::<_,i64>(3)?
                    }))
                },
            )?
        }
        "config-save" => {
            let key = id(&v)?;
            own(&tx, &u, "configs", key)?;
            if let Some(expected) = v["revision"].as_i64() {
                let current: i64 =
                    tx.query_row("select revision from configs where id=?", [key], |r| {
                        r.get(0)
                    })?;
                ensure!(
                    current == expected,
                    "another tab updated these sources; reopen before editing"
                );
            }
            for (field, sql) in [
                ("note", "update configs set note=? where id=?"),
                (
                    "sr",
                    "update configs set sr=?,revision=revision+1 where id=?",
                ),
                (
                    "base",
                    "update configs set base=?,revision=revision+1 where id=?",
                ),
            ] {
                if v.get(field).is_some() {
                    tx.execute(sql, params![string(&v, field)?, key])?;
                }
            }
            Value::Null
        }
        "compile" => {
            let key = id(&v)?;
            own(&tx, &u, "configs", key)?;
            let (p, rev) = publication.context("missing compilation")?;
            let n = tx.execute(
                "update configs set output=? where id=? and revision=?",
                params![p.config.to_string(), key, rev],
            )?;
            ensure!(n == 1, "uploads changed, compile again");
            for (tag, bytes) in p.files {
                tx.execute(
                    "insert or ignore into blobs(tag,bytes) values(?,?)",
                    params![tag, bytes],
                )?;
            }
            Value::Null
        }
        "link-new" => {
            let token = match v
                .get("token")
                .and_then(Value::as_str)
                .filter(|x| !x.is_empty())
            {
                Some(t) => t.to_string(),
                None => loop {
                    let t = store::token(store::URLSAFE);
                    if !tx.query_row(
                        "select exists(select 1 from links where token=?)",
                        [&t],
                        |r| r.get::<_, bool>(0),
                    )? {
                        break t;
                    }
                },
            };
            ensure!(
                token.len() == 43 && token.bytes().all(|b| store::URLSAFE.contains(&b)),
                "link token must contain 43 URL-safe characters"
            );
            tx.execute(
                "insert into links(owner,note,token) values (?,?,?)",
                params![u.owner, string(&v, "note")?, token],
            )?;
            json!(token)
        }
        "link-save" => {
            let key = id(&v)?;
            let owner = own(&tx, &u, "links", key)?;
            if v.get("note").is_some() {
                tx.execute(
                    "update links set note=? where id=?",
                    params![string(&v, "note")?, key],
                )?;
            }
            if let Some(target) = v.get("target") {
                let target = if target.is_null() {
                    None
                } else {
                    Some(target.as_i64().context("invalid target")?)
                };
                if let Some(t) = target {
                    ensure!(
                        own(&tx, &u, "configs", t)? == owner,
                        "target owner mismatch"
                    );
                }
                tx.execute("update links set target=? where id=?", params![target, key])?;
            }
            Value::Null
        }
        "admin" => {
            admin(&u)?;
            json!({"settings":s.json(),"listen":tx.query_row("select listen from settings",[],|r|r.get::<_,String>(0))?,
            "has_password":tx.query_row("select password is not null from settings",[],|r|r.get::<_,bool>(0))?,
            "roles":rows(&tx,"select issuer,sub,role from roles order by issuer,sub",[],|r|Ok(json!({"issuer":r.get::<_,String>(0)?,"sub":r.get::<_,String>(1)?,"role":r.get::<_,String>(2)?})))?})
        }
        "settings" => {
            admin(&u)?;
            let public = string(&v, "public")?.trim_end_matches('/');
            let url = url::Url::parse(public)?;
            ensure!(
                matches!(url.scheme(), "https" | "http")
                    && url.has_host()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.username().is_empty()
                    && url.password().is_none(),
                "expected public origin"
            );
            let issuer = string(&v, "issuer")?;
            let client = string(&v, "client")?;
            let aud = string(&v, "audience")?;
            if !issuer.is_empty() {
                ensure!(
                    identity::endpoint(issuer)?.query().is_none()
                        && !client.is_empty()
                        && !aud.is_empty(),
                    "issuer, client ID and audience required"
                );
            }
            let imports: Vec<String> = serde_json::from_value(v["imports"].clone())?;
            for i in &imports {
                identity::endpoint(i)?;
            }
            let bind = store::listener(string(&v, "listen")?)?;
            tx.execute("update settings set listen=?,public_url=?,issuer=?,client_id=?,audience=?,scope=?,imports=?,auth_epoch=auth_epoch+1",params![bind,public,issuer,client,aud,string(&v,"scope")?,json!(imports).to_string()])?;
            Value::Null
        }
        "role" => {
            admin(&u)?;
            let issuer = string(&v, "issuer")?;
            let sub = string(&v, "sub")?;
            let role = string(&v, "role")?;
            ensure!(
                !issuer.is_empty() && !sub.is_empty() && issuer == s.issuer,
                "expected current issuer and a nonempty sub"
            );
            if role == "guest" {
                tx.execute(
                    "delete from roles where issuer=? and sub=?",
                    params![issuer, sub],
                )?;
            } else {
                tx.execute("insert into roles values(?,?,?) on conflict(issuer,sub) do update set role=excluded.role",params![issuer,sub,role])?;
            }
            Value::Null
        }
        "password" => {
            admin(&u)?;
            let value = if v["password"].is_null() {
                None
            } else {
                Some(store::hash(string(&v, "password")?)?)
            };
            tx.execute("update settings set password=?", [value])?;
            tx.execute("delete from sessions", [])?;
            Value::Null
        }
        "purge-keys" => {
            admin(&u)?;
            app.discovery.clear();
            Value::Null
        }
        _ => bail!("not found"),
    };
    if matches!(op.as_str(), "settings" | "role" | "password") {
        let ok:bool=tx.query_row("select password is not null or exists(select 1 from roles where issuer=settings.issuer and role='admin') from settings",[],|r|r.get(0))?;
        ensure!(
            ok,
            "keep an administrator for the active issuer before removing password access"
        );
    }
    tx.commit()?;
    Ok(value)
}
