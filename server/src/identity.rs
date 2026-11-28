use crate::store::{Settings, now};
use anyhow::{Context, Result, bail, ensure};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};
use reqwest::blocking::{Client, Response};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::Read,
    sync::Mutex,
    time::{Duration, UNIX_EPOCH},
};
use url::Url;

pub fn endpoint(raw: &str) -> Result<Url> {
    let u = Url::parse(raw)?;
    ensure!(
        u.scheme() == "https"
            && u.has_host()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none(),
        "expected HTTPS URL"
    );
    Ok(u)
}
fn http() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
fn body(r: Response) -> Result<Value> {
    let mut buf = Vec::new();
    r.error_for_status()?
        .take(1_048_577)
        .read_to_end(&mut buf)?;
    ensure!(buf.len() <= 1_048_576, "identity response too large");
    Ok(serde_json::from_slice(&buf)?)
}

#[derive(Default)]
pub struct Discovery(Mutex<HashMap<(i64, String), (i64, Value)>>);
impl Discovery {
    pub fn clear(&self) {
        self.0.lock().unwrap().clear()
    }
    fn get(&self, epoch: i64, url: &str) -> Result<Value> {
        endpoint(url)?;
        let key = (epoch, url.to_string());
        // Serialize fills, so concurrent requests cannot stampede a rotating issuer.
        let mut cache = self.0.lock().unwrap();
        let time = now();
        cache.retain(|_, (until, _)| *until > time);
        if let Some((_, item)) = cache.get(&key) {
            return Ok(item.clone());
        }
        let response = http()?.get(url).send()?;
        let heads = response.headers();
        let header = |name: &str| heads.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
        let date = |name: &str| {
            httpdate::parse_http_date(header(name))
                .ok()
                .and_then(|d| d.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
        };
        let mut ttl = date("expires")
            .map(|exp| exp.saturating_sub(date("date").unwrap_or(time)))
            .unwrap_or(300);
        let mut uncached = false;
        for line in heads
            .get_all("cache-control")
            .iter()
            .filter_map(|h| h.to_str().ok())
        {
            for directive in line.to_ascii_lowercase().split(',').map(str::trim) {
                if matches!(directive.split('=').next(), Some("no-cache" | "no-store")) {
                    uncached = true;
                }
                if let Some(age) = directive.strip_prefix("max-age=") {
                    ttl = age.trim_matches('"').parse().unwrap_or(0);
                }
            }
        }
        let age = header("age")
            .parse::<i64>()
            .unwrap_or(0)
            .max(time.saturating_sub(date("date").unwrap_or(time)))
            .max(0);
        ttl = ttl.saturating_sub(age).clamp(0, 7 * 86400);
        let v = body(response)?;
        if !uncached && ttl > 0 {
            cache.insert(key, (time + ttl, v.clone()));
        }
        Ok(v)
    }
    pub fn metadata(&self, s: &Settings) -> Result<Value> {
        let issuer = endpoint(&s.issuer)?;
        ensure!(issuer.query().is_none(), "invalid issuer");
        let oauth = format!(
            "{}/.well-known/oauth-authorization-server{}",
            issuer.origin().ascii_serialization(),
            issuer.path().trim_end_matches('/')
        );
        let oidc = format!(
            "{}/.well-known/openid-configuration",
            s.issuer.trim_end_matches('/')
        );
        let m = self
            .get(s.epoch, &oauth)
            .or_else(|_| self.get(s.epoch, &oidc))?;
        ensure!(
            m["issuer"].as_str() == Some(s.issuer.as_str()),
            "discovery issuer mismatch"
        );
        Ok(m)
    }
    pub fn verify(&self, s: &Settings, token: &str) -> Result<String> {
        let h = decode_header(token)?;
        ensure!(
            h.typ
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("at+jwt")
                    || t.eq_ignore_ascii_case("application/at+jwt")),
            "expected access token"
        );
        ensure!(
            matches!(
                h.alg,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
                    | Algorithm::ES256
                    | Algorithm::ES384
                    | Algorithm::EdDSA
            ),
            "asymmetric access token required"
        );
        let m = self.metadata(s)?;
        let keys = self.get(s.epoch, m["jwks_uri"].as_str().context("missing jwks_uri")?)?;
        let mut v = Validation::new(h.alg);
        v.set_issuer(&[&s.issuer]);
        v.set_audience(&[&s.audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        v.validate_nbf = true;
        v.leeway = 1;
        for k in keys["keys"].as_array().context("invalid JWKS")? {
            if h.kid
                .as_ref()
                .is_some_and(|kid| k["kid"].as_str() != Some(kid.as_str()))
                || k["use"].as_str().is_some_and(|u| u != "sig")
                || k["key_ops"]
                    .as_array()
                    .is_some_and(|ops| !ops.iter().any(|v| v == "verify"))
                || k["alg"]
                    .as_str()
                    .is_some_and(|a| a != format!("{:?}", h.alg))
            {
                continue;
            }
            let jwk: Jwk = match serde_json::from_value(k.clone()) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let Ok(key) = DecodingKey::from_jwk(&jwk) else {
                continue;
            };
            if let Ok(data) = decode::<Value>(token, &key, &v) {
                let c = data.claims;
                ensure!(
                    c["client_id"].as_str() == Some(s.client.as_str())
                        && c["iat"].as_i64().is_some_and(|i| i <= now() + 1)
                        && c["jti"].as_str().is_some_and(|s| !s.is_empty()),
                    "invalid access token claims"
                );
                return Ok(c["sub"]
                    .as_str()
                    .filter(|x| !x.is_empty())
                    .context("missing sub")?
                    .to_owned());
            }
        }
        bail!("access token validation failed")
    }
    pub fn exchange(&self, s: &Settings, code: &str, verifier: &str) -> Result<String> {
        let m = self.metadata(s)?;
        let url = endpoint(
            m["token_endpoint"]
                .as_str()
                .context("missing token endpoint")?,
        )?;
        let redirect = format!("{}/", s.public);
        let response = body(
            http()?
                .post(url)
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("client_id", &s.client),
                    ("code", code),
                    ("redirect_uri", &redirect),
                    ("code_verifier", verifier),
                ])
                .send()?,
        )?;
        Ok(response["access_token"]
            .as_str()
            .context("missing access token")?
            .to_owned())
    }
}
