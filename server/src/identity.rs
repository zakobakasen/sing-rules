use crate::store::{Settings, now};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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

#[derive(Debug)]
pub struct TokenError {
    pub field: &'static str,
    pub actual: String,
    pub expected: String,
    pub code: &'static str,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "访问令牌的 {} 校验失败。实际值为 {}，预期为 {}",
            self.field, self.actual, self.expected
        )
    }
}
impl std::error::Error for TokenError {}

fn invalid(
    field: &'static str,
    actual: impl Into<String>,
    expected: impl Into<String>,
) -> TokenError {
    TokenError {
        field,
        actual: actual.into(),
        expected: expected.into(),
        code: "invalid_token",
    }
}

fn observed(value: Option<&Value>) -> String {
    value
        .map(Value::to_string)
        .unwrap_or_else(|| "（缺失）".into())
}

fn claims(c: &Value, s: &Settings) -> Result<String> {
    let current = now();
    for (field, expected) in [("iss", &s.issuer), ("client_id", &s.client)] {
        if c[field].as_str() != Some(expected.as_str()) {
            return Err(invalid(field, observed(c.get(field)), expected).into());
        }
    }
    let aud = &c["aud"];
    if !(aud.as_str() == Some(s.audience.as_str())
        || aud.as_array().is_some_and(|a| {
            a.iter().all(Value::is_string)
                && a.iter().any(|v| v.as_str() == Some(s.audience.as_str()))
        }))
    {
        return Err(invalid(
            "aud",
            observed(c.get("aud")),
            format!("{} 或包含该值的字符串数组", s.audience),
        )
        .into());
    }
    for field in ["sub", "jti"] {
        if !c[field].as_str().is_some_and(|s| !s.is_empty()) {
            return Err(invalid(field, observed(c.get(field)), "非空字符串").into());
        }
    }
    for field in ["iat", "nbf", "exp"] {
        if field == "nbf" && c.get(field).is_none() {
            continue;
        }
        let timestamp = c[field]
            .as_i64()
            .ok_or_else(|| invalid(field, observed(c.get(field)), "Unix 时间戳（整数秒）"))?;
        if field == "exp" && timestamp < current - 1 {
            let mut error = invalid(
                field,
                timestamp.to_string(),
                format!(
                    "不早于 {}（服务器 Unix 时间 {}，允许 1 秒偏差）",
                    current - 1,
                    current
                ),
            );
            error.code = "token_expired";
            return Err(error.into());
        }
        if field != "exp" && timestamp > current + 1 {
            return Err(invalid(
                field,
                timestamp.to_string(),
                format!(
                    "不晚于 {}（服务器 Unix 时间 {}，允许 1 秒偏差）",
                    current + 1,
                    current
                ),
            )
            .into());
        }
    }
    Ok(c["sub"].as_str().unwrap().to_owned())
}

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
        let h = decode_header(token).map_err(|_| {
            let mut parts = token.split('.');
            let encoded = parts.next().unwrap_or("");
            if parts.count() != 2 {
                return invalid("JWT", "段数错误", "header.payload.signature 三段");
            }
            let header = URL_SAFE_NO_PAD
                .decode(encoded)
                .ok()
                .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
            match header {
                Some(header) if header.is_object() => {
                    for field in ["typ", "kid"] {
                        if let Some(value) = header.get(field)
                            && !value.is_string()
                        {
                            return invalid(field, value.to_string(), "字符串");
                        }
                    }
                    invalid(
                        "alg",
                        observed(header.get("alg")),
                        "受支持的 JWT 非对称签名算法",
                    )
                }
                _ => invalid("JWT header", "无法解析标头", "Base64url 编码的 JSON 对象"),
            }
        })?;
        if !h.typ.as_deref().is_some_and(|t| {
            t.eq_ignore_ascii_case("at+jwt") || t.eq_ignore_ascii_case("application/at+jwt")
        }) {
            return Err(invalid(
                "typ",
                h.typ.as_deref().unwrap_or("（缺失）"),
                "at+jwt 或 application/at+jwt",
            )
            .into());
        }
        if !matches!(
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
        ) {
            return Err(invalid(
                "alg",
                format!("{:?}", h.alg),
                "RS256/384/512、PS256/384/512、ES256/384 或 EdDSA",
            )
            .into());
        }
        let m = self.metadata(s).context("无法读取 IdP 发现文档")?;
        let keys = self
            .get(
                s.epoch,
                m["jwks_uri"].as_str().context("发现文档缺少 jwks_uri")?,
            )
            .context("无法读取 IdP 公钥")?;
        let keys = keys["keys"].as_array().context("JWKS 缺少 keys 数组")?;
        if let Some(kid) = &h.kid
            && !keys.iter().any(|k| k["kid"].as_str() == Some(kid))
        {
            let ids: Vec<_> = keys.iter().filter_map(|k| k["kid"].as_str()).collect();
            return Err(invalid("kid", kid, format!("已发布的公钥标识 {ids:?}")).into());
        }
        // Verify the signature first. The typed checks below then inspect authenticated claims.
        let mut v = Validation::new(h.alg);
        v.required_spec_claims.clear();
        v.validate_exp = false;
        v.validate_aud = false;
        let mut tried = false;
        for k in keys {
            if h.kid
                .as_ref()
                .is_some_and(|id| k["kid"].as_str() != Some(id))
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
            let Ok(jwk) = serde_json::from_value::<Jwk>(k.clone()) else {
                continue;
            };
            let Ok(key) = DecodingKey::from_jwk(&jwk) else {
                continue;
            };
            tried = true;
            match decode::<Value>(token, &key, &v) {
                Ok(data) => return claims(&data.claims, s),
                Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::Json(_)) => {
                    return Err(
                        invalid("payload", "无法解析 JWT JSON", "有效的 JWT 声明对象").into(),
                    );
                }
                Err(_) => continue,
            }
        }
        let actual = if tried {
            "签名未通过验证"
        } else {
            "无可用验签公钥"
        };
        Err(invalid(
            "signature",
            actual,
            format!(
                "可由已配置 IdP 的公钥验证的 {:?} 签名（kid={:?}）",
                h.alg, h.kid
            ),
        )
        .into())
    }
}
