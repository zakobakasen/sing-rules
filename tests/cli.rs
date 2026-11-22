use serde_json::{Value, json};
use std::{
    fs,
    process::{Command, Output},
};
use tempfile::TempDir;

struct Project(TempDir);

impl Project {
    fn new() -> Self {
        let project = Self(tempfile::tempdir().unwrap());
        project.write("base.json", r#"{"outbounds":[{"type":"direct","tag":"Proxy"},{"type":"direct","tag":"Direct"},{"type":"direct","tag":"Aliyun"}]}"#);
        project
    }

    fn write(&self, file: &str, contents: &str) {
        fs::write(self.0.path().join(file), contents).unwrap();
    }

    fn run(&self, declarations: &str, table: &str) -> Output {
        self.run_with(declarations, table, &[])
    }

    fn run_with(&self, declarations: &str, table: &str, extra: &[&str]) -> Output {
        self.write("routes.rules", &format!(
            "outbounds {{\n Proxy\n Direct\n Aliyun\n}}\n{declarations}\nroute {{\n{table}\n}}\n"
        ));
        Command::new(env!("CARGO_BIN_EXE_sing-rules"))
            .current_dir(self.0.path())
            .args([
                "compile",
                "routes.rules",
                "--base",
                "base.json",
                "-o",
                "compiled.json",
                "--cache-dir",
                "ruleset-cache",
            ])
            .args(extra)
            .output()
            .unwrap()
    }

    fn compile(&self, declarations: &str, table: &str) -> Value {
        let output = self.run(declarations, table);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&fs::read(self.0.path().join("compiled.json")).unwrap()).unwrap()
    }

    fn error(&self, declarations: &str, table: &str, expected: &str) {
        let output = self.run(declarations, table);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{stderr}");
    }
}

#[test]
fn compiles_the_agreed_syntax_and_native_private_ip() {
    let project = Project::new();
    project.write(
        "cn.json",
        r#"{"version":2,"rules":[{"ip_cidr":["203.0.113.0/24"]}]}"#,
    );
    let config = project.compile(
        r#"ruleset cn = file("./cn.json")"#,
        "
        IP, 1.1.1.1/32, Proxy
        2001:db8::1, Direct
        Domain, A.com., Direct
        DomainSuffix, *.a.com, Aliyun
        RuleSet, cn, Aliyun
        RuleSet, PrivateIP, Direct
        *, Proxy
    ",
    );
    let route = &config["route"];
    assert_eq!(route["final"], "Proxy");
    let rules = route["rules"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .any(|rule| rule["domain"] == json!(["a.com", "a.com."]))
    );
    assert!(
        rules
            .iter()
            .any(|rule| rule["domain_suffix"] == json!([".a.com", ".a.com."]))
    );
    assert!(rules.iter().any(|rule| rule["ip_is_private"] == true));
    assert!(route.get("rule_set").is_none());
    if let Some(binary) = std::env::var_os("SING_BOX") {
        let checked = Command::new(binary)
            .current_dir(project.0.path())
            .args(["check", "-c", "compiled.json"])
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }
}

#[test]
fn merges_unrelated_prefixes_across_lengths_and_is_order_independent() {
    let project = Project::new();
    let rows = [
        "10.0.0.0/8, Direct",
        "10.1.0.0/16, Reject",
        "10.1.2.0/24, Direct",
        "172.16.1.0/24, Reject",
        "*, Proxy",
    ];
    let initial = project.compile("", &rows.join("\n"));
    let shuffled = project.compile("", &rows.into_iter().rev().collect::<Vec<_>>().join("\n"));
    assert_eq!(initial, shuffled);
    let rules = initial["route"]["rules"].as_array().unwrap();
    let pivot = rules
        .iter()
        .position(|rule| rule["action"] == "resolve")
        .unwrap();
    assert_eq!(pivot, 4); // Three first-pass matchers and the known-IP fallback.
    assert_eq!(rules[3]["outbound"], "Proxy");
    assert_eq!(rules[3]["ip_cidr"], json!(["0.0.0.0/0", "::/0"]));
    assert_eq!(rules[0]["outbound"], "Direct");
    assert_eq!(rules[1]["action"], "reject");
    assert_eq!(rules[1]["ip_cidr"].as_array().unwrap().len(), 4);
    assert_eq!(rules[2]["outbound"], "Direct");
}

#[test]
fn validates_names_references_and_normalized_conflicts() {
    let project = Project::new();
    project.error("", "@cn, Proxy\n*, Direct", "explicit RuleSet");
    project.error("", "RuleSet, cn, Proxy\n*, Direct", "unknown ruleset");
    project.error(
        r#"ruleset c/n = file("cn.json")"#,
        "*, Direct",
        "ruleset name",
    );
    project.error(
        r#"ruleset PrivateIP = file("cn.json")"#,
        "*, Direct",
        "reserved",
    );
    project.error("", "a.com, Missing\n*, Direct", "undeclared outbound");
    project.error(
        "",
        "::ffff:1.2.3.4, Proxy\n1.2.3.4, Direct\n*, Proxy",
        "conflict",
    );
    project.error("", "IP, [1.1.1.1, 1.0.0.1], Proxy\n*, Direct", "expected");
    project.error("", "1.1.1.1, Proxy", "fallback");
}

#[test]
fn warns_and_keeps_supported_ruleset_fields() {
    let project = Project::new();
    project.write("ads.json", r#"{"version":4,"rules":[
        {"domain_regex":["^only-regex"],"domain":["ads.example"],"domain_suffix":["tracker.example"],"ip_cidr":["203.0.113.0/24"]},
        {"domain_keyword":["keyword"]},
        {"port":[80],"domain":["port-qualified.example"]},
        {"type":"logical","mode":"and","rules":[{"domain":["ignored.example"]},{"port":[80]}]},
        {"invert":true,"domain":["negated.example"]},
        {"type":"logical","mode":"or","rules":[{"domain_keyword":["keyword"]},{"domain":"or.example"}]}
    ]}"#);
    let output = project.run(
        r#"ruleset ads = file("ads.json")"#,
        "RuleSet, ads, Reject\n*, Proxy",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    for part in [
        "warning:",
        "ads.json:rules[0]",
        "domain_regex",
        "domain_keyword",
        "port",
        "and",
        "invert",
    ] {
        assert!(stderr.contains(part), "missing {part}: {stderr}");
    }
    let config =
        serde_json::from_slice(&fs::read(project.0.path().join("compiled.json")).unwrap()).unwrap();
    for host in [
        "ads.example",
        "x.tracker.example",
        "port-qualified.example",
        "or.example",
    ] {
        assert_eq!(output_match(&config, Some(host), None), "Reject", "{host}");
    }
    for host in [
        "only-regex.example",
        "keyword.example",
        "ignored.example",
        "negated.example",
    ] {
        assert_eq!(output_match(&config, Some(host), None), "Proxy", "{host}");
    }
    assert_eq!(
        output_match(&config, None, Some("203.0.113.4".parse().unwrap())),
        "Reject"
    );
}

#[test]
fn still_rejects_malformed_supported_ruleset_fields() {
    let project = Project::new();
    project.write(
        "ads.json",
        r#"{"version":4,"rules":[{"domain_regex":["x"],"ip_cidr":["bad-ip"]}]}"#,
    );
    project.error(
        r#"ruleset ads = file("ads.json")"#,
        "RuleSet, ads, Reject\n*, Proxy",
        "rules[0].ip_cidr[0]",
    );
}

#[test]
fn distinguishes_family_defaults_and_global_reject() {
    let project = Project::new();
    let config = project.compile("", "0.0.0.0/0, Direct\n::/0, Aliyun\n*, Reject");
    let rules = config["route"]["rules"].as_array().unwrap();
    assert!(rules.iter().any(|rule| rule["outbound"] == "Direct"));
    assert!(rules.iter().any(|rule| rule["outbound"] == "Aliyun"));
    assert_eq!(rules.last().unwrap(), &json!({"action":"reject"}));
    assert!(config["route"].get("final").is_none());
}

#[test]
fn handles_inclusive_imports_and_strict_suffix_exceptions() {
    let project = Project::new();
    project.write(
        "sites.json",
        r#"{"version":5,"rules":[{"domain_suffix":["a.com"]}]}"#,
    );
    let config = project.compile(
        r#"ruleset sites = file("sites.json")"#,
        "
        RuleSet, sites, Direct
        *.a.com, Aliyun
        api.a.com, Reject
        *, Proxy
    ",
    );
    for (host, target) in [
        ("a.com", "Direct"),
        ("b.a.com", "Aliyun"),
        ("x.b.a.com", "Aliyun"),
        ("api.a.com", "Reject"),
        ("nota.com", "Proxy"),
    ] {
        assert_eq!(output_match(&config, Some(host), None), target, "{host}");
    }
}

#[test]
fn randomized_prefixes_match_reference_lookup() {
    use ipnet::IpNet;
    use std::{
        collections::BTreeMap,
        net::{Ipv4Addr, Ipv6Addr},
    };

    let project = Project::new();
    let mut state = 0x65ad_d232_4872_155bu64;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        state >> 32
    };
    let targets = ["Direct", "Aliyun", "Proxy", "Reject"];

    for _ in 0..24 {
        let mut rules = BTreeMap::new();
        for _ in 0..55 {
            let bits = next() as u32;
            let prefix = (next() % 18) as u8;
            let network = if next() & 1 == 0 {
                IpNet::new(Ipv4Addr::from(bits).into(), prefix).unwrap()
            } else {
                IpNet::new(Ipv6Addr::from(u128::from(bits) << 96).into(), prefix).unwrap()
            };
            rules.insert(network.trunc(), targets[(next() % 4) as usize]);
        }
        let rows = rules
            .iter()
            .map(|(net, target)| format!("{net}, {target}"))
            .collect::<Vec<_>>();
        let config = project.compile("", &format!("{}\n*, Proxy", rows.join("\n")));
        for _ in 0..250 {
            let bits = next() as u32;
            let v4 = Ipv4Addr::from(bits);
            let addresses = [
                v4.into(),
                v4.to_ipv6_mapped().into(),
                Ipv6Addr::from(u128::from(bits) << 96).into(),
            ];
            for ip in addresses {
                let normalized = std::net::IpAddr::to_canonical(&ip);
                let expected = rules
                    .iter()
                    .filter(|(net, _)| net.contains(&normalized))
                    .max_by_key(|(net, _)| net.prefix_len())
                    .map_or("Proxy", |(_, target)| target);
                assert_eq!(output_match(&config, None, Some(ip)), expected, "{ip}");
            }
        }
    }
}

fn output_match(config: &Value, host: Option<&str>, ip: Option<std::net::IpAddr>) -> String {
    let route = &config["route"];
    let matched = route["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["action"] != "resolve" && matches_output(rule, host, ip));
    match matched {
        Some(rule) if rule["action"] == "reject" => "Reject",
        Some(rule) => rule["outbound"].as_str().unwrap(),
        None => route["final"].as_str().unwrap(),
    }
    .to_string()
}

fn matches_output(rule: &Value, host: Option<&str>, ip: Option<std::net::IpAddr>) -> bool {
    matches_output_ips(rule, host, ip.as_slice())
}

fn matches_output_ips(rule: &Value, host: Option<&str>, ips: &[std::net::IpAddr]) -> bool {
    let matched = if rule["type"] == "logical" {
        let mut children = rule["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|child| matches_output_ips(child, host, ips));
        if rule["mode"] == "and" {
            children.all(|result| result)
        } else {
            children.any(|result| result)
        }
    } else {
        let has_conditions = ["domain", "domain_suffix", "ip_cidr", "ip_is_private"]
            .iter()
            .any(|field| rule.get(field).is_some());
        !has_conditions
            || host.is_some_and(|host| {
                field_items(rule, "domain").any(|name| name == host)
                    || field_items(rule, "domain_suffix").any(|name| {
                        host == name
                            || if name.starts_with('.') {
                                host.ends_with(name)
                            } else {
                                host.strip_suffix(name)
                                    .is_some_and(|prefix| prefix.ends_with('.'))
                            }
                    })
            })
            || field_items(rule, "ip_cidr").any(|net| {
                let net = net.parse::<ipnet::IpNet>().unwrap();
                ips.iter().any(|ip| net.contains(ip))
            })
    };
    matched ^ (rule["invert"] == true)
}

fn field_items<'a>(value: &'a Value, field: &str) -> impl Iterator<Item = &'a str> {
    value[field]
        .as_array()
        .into_iter()
        .flatten()
        .map(|v| v.as_str().unwrap())
}

#[test]
fn expands_srs_with_real_sing_box() {
    let Some(binary) = std::env::var_os("SING_BOX") else {
        return;
    };
    let project = Project::new();
    project.write(
        "source.json",
        r#"{"version":5,"rules":[{"ip_cidr":["192.168.1.0/24"],"domain_suffix":[".a.com"]}]}"#,
    );
    let encoded = Command::new(&binary)
        .current_dir(project.0.path())
        .args(["rule-set", "compile", "-o", "source.srs", "source.json"])
        .output()
        .unwrap();
    assert!(
        encoded.status.success(),
        "{}",
        String::from_utf8_lossy(&encoded.stderr)
    );
    project.write("routes.rules", "outbounds {\nDirect\nProxy\n}\nruleset sites = file(\"source.srs\")\nroute {\nRuleSet, sites, Direct\n*, Proxy\n}\n");
    let result = Command::new(env!("CARGO_BIN_EXE_sing-rules"))
        .current_dir(project.0.path())
        .args([
            "compile",
            "routes.rules",
            "--base",
            "base.json",
            "--sing-box",
        ])
        .arg(binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let config = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(output_match(&config, Some("b.a.com"), None), "Direct");
    assert_eq!(output_match(&config, Some("a.com"), None), "Proxy");
    assert_eq!(
        output_match(&config, None, Some("192.168.1.42".parse().unwrap())),
        "Direct"
    );
}

#[test]
#[ignore = "requires permission to start a local sing-box service"]
fn verifies_real_routing_with_sniffed_domain_and_destination_ip() {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        process::Stdio,
        thread,
        time::Duration,
    };

    let binary = std::env::var_os("SING_BOX_RUNTIME")
        .expect("set SING_BOX_RUNTIME to the sing-box executable");
    let project = Project::new();
    let mut config = project.compile(
        "",
        "
        127.0.0.1, Aliyun
        RuleSet, PrivateIP, Reject
        a.com, Direct
        *.a.com, Reject
        *, Proxy
    ",
    );
    let inbound = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = inbound.local_addr().unwrap().port();
    drop(inbound);
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let destination = sink.local_addr().unwrap();
    let sink_thread = thread::spawn(move || {
        sink.set_nonblocking(true).unwrap();
        let finish = std::time::Instant::now() + Duration::from_secs(6);
        let mut completed = 0;
        while completed < 3 && std::time::Instant::now() < finish {
            match sink.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK");
                    completed += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        }
        completed
    });
    config["inbounds"] = json!([{"type":"socks","listen":"127.0.0.1","listen_port":port}]);
    config["log"] = json!({"level":"debug","output":"box.log"});
    config["route"]["rules"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"action":"sniff","sniffer":["http"]}));
    project.write("runtime.json", &config.to_string());
    let mut box_process = BoxProcess(
        Command::new(binary)
            .current_dir(project.0.path())
            .args(["run", "-c", "runtime.json"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );

    for (host, allow) in [
        ("a.com", true),
        ("b.a.com", false),
        ("nota.com", true),
        ("a.com.", true),
    ] {
        let mut stream = (0..40)
            .find_map(|_| {
                TcpStream::connect(("127.0.0.1", port)).ok().or_else(|| {
                    thread::sleep(Duration::from_millis(25));
                    None
                })
            })
            .expect("sing-box SOCKS listener available");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&[5, 1, 0]).unwrap();
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(destination.port().to_be_bytes());
        stream.write_all(&request).unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0);
        stream
            .write_all(format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert_eq!(response.contains("200 OK"), allow, "{host}");
    }
    box_process.0.kill().unwrap();
    box_process.0.wait().unwrap();
    let logs = fs::read_to_string(project.0.path().join("box.log")).unwrap();
    assert!(logs.contains("route(Direct)"), "{logs}");
    assert!(logs.contains("route(Aliyun)"), "{logs}");
    assert_eq!(sink_thread.join().unwrap(), 3);
}

struct BoxProcess(std::process::Child);

impl Drop for BoxProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn verifies_generated_conditions_with_real_sing_box() {
    let Some(binary) = std::env::var_os("SING_BOX") else {
        return;
    };
    let project = Project::new();
    let config = project.compile(
        "",
        "
        127.0.0.1, Aliyun
        0.0.0.0/0, Direct
        ::/0, Aliyun
        a.com, Direct
        *.a.com, Aliyun
        RuleSet, PrivateIP, Reject
        *, Proxy
    ",
    );
    let checked = Command::new(&binary)
        .current_dir(project.0.path())
        .args(["check", "-c", "compiled.json"])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    // Exercise generated matchers with sing-box's headless rule implementation.
    for (index, rule) in config["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut condition = rule.clone();
        let fields = condition.as_object_mut().unwrap();
        fields.remove("action");
        fields.remove("outbound");
        if fields.is_empty() || fields.contains_key("ip_is_private") {
            // ip_is_private is a route-only field.
            continue;
        }
        project.write(
            &format!("rule-{index}.json"),
            &json!({"version":5,"rules":[condition]}).to_string(),
        );
        for target in [
            "a.com",
            "b.a.com",
            "x.y.a.com",
            "nota.com",
            "127.0.0.1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ] {
            let result = Command::new(&binary)
                .current_dir(project.0.path())
                .args(["rule-set", "match", &format!("rule-{index}.json"), target])
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let matched = String::from_utf8_lossy(&result.stderr).contains("match rules.");
            let ip = target.parse().ok();
            let domain = ip.is_none().then_some(target);
            assert_eq!(
                matched,
                matches_output(rule, domain, ip),
                "rule {rule}, target {target}"
            );
        }
    }
}

fn serve_ruleset(
    listener: std::net::TcpListener,
    payload: &'static str,
) -> std::thread::JoinHandle<()> {
    use std::{
        io::{BufRead, BufReader, Write},
        thread,
        time::Duration,
    };

    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let mut stream = (0..150)
            .find_map(|_| {
                listener.accept().ok().or_else(|| {
                    thread::sleep(Duration::from_millis(20));
                    None
                })
            })
            .expect("expected HTTP request")
            .0;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = BufReader::new(&mut stream);
        loop {
            let mut line = String::new();
            if request.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        )
        .unwrap();
    })
}

#[test]
fn caches_remote_rulesets_across_compiles_and_refreshes_them() {
    use std::{
        fs::FileTimes,
        net::TcpListener,
        time::{Duration, SystemTime},
    };
    const ORIGINAL: &str = r#"{"version":2,"rules":[{"ip_cidr":["203.0.113.0/24"]}]}"#;
    const UPDATED: &str = r#"{"version":2,"rules":[{"domain":"new.example"}]}"#;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = serve_ruleset(listener.try_clone().unwrap(), ORIGINAL);
    let project = Project::new();
    let declarations = format!(
        "ruleset c.n~1 = url(\"http://{addr}/ip.json\")\nruleset alias = url(\"http://{addr}/ip.json\")"
    );
    let table = "RuleSet, c.n~1, Aliyun\nRuleSet, alias, Aliyun\n*, Proxy";
    let first = project.compile(&declarations, table);
    server.join().unwrap();
    assert_eq!(
        output_match(&first, None, Some("203.0.113.4".parse().unwrap())),
        "Aliyun"
    );
    assert_eq!(project.compile(&declarations, table), first);

    let server = serve_ruleset(listener.try_clone().unwrap(), "an invalid download");
    let failed = project.run_with(&declarations, table, &["--refresh"]);
    assert!(!failed.status.success());
    server.join().unwrap();
    assert_eq!(project.compile(&declarations, table), first);

    let server = serve_ruleset(listener.try_clone().unwrap(), UPDATED);
    let output = project.run_with(&declarations, table, &["--refresh"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    let updated = project.compile(&declarations, table);
    assert_eq!(output_match(&updated, Some("new.example"), None), "Aliyun");

    let cache = project.0.path().join("ruleset-cache");
    let entry = fs::read_dir(cache).unwrap().next().unwrap().unwrap().path();
    std::fs::File::open(entry)
        .unwrap()
        .set_times(
            FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(25 * 3600)),
        )
        .unwrap();
    let server = serve_ruleset(listener, ORIGINAL);
    assert_eq!(project.compile(&declarations, table), first);
    server.join().unwrap();
}

#[test]
fn resolves_only_domain_misses_and_rechecks_only_ip_rules() {
    let project = Project::new();
    let config = project.compile(
        "",
        "
        a.com, Reject
        203.0.113.0/24, Direct
        192.0.2.0/24, Reject
        2001:db8::/32, Aliyun
        *, Proxy
    ",
    );
    let rules = config["route"]["rules"].as_array().unwrap();
    let pivot = rules
        .iter()
        .position(|rule| rule["action"] == "resolve")
        .expect("DNS fallback");
    assert!(
        rules[..pivot]
            .iter()
            .any(|rule| rule["action"] == "reject" && rule.get("domain").is_some())
    );
    assert!(
        rules[pivot + 1..]
            .iter()
            .all(|rule| rule.get("domain").is_none() && rule.get("domain_suffix").is_none())
    );

    let expected_routes = [
        (Some("a.com"), None, &[][..], ("Reject", false)),
        (
            Some("a.com"),
            Some("203.0.113.4"),
            &[][..],
            ("Reject", false),
        ),
        (
            Some("b.com"),
            Some("203.0.113.4"),
            &[][..],
            ("Direct", false),
        ),
        (
            Some("b.com"),
            Some("198.51.100.8"),
            &["192.0.2.1"][..],
            ("Proxy", false),
        ),
        (None, Some("198.51.100.8"), &[][..], ("Proxy", false)),
        (Some("b.com"), None, &["203.0.113.4"][..], ("Direct", true)),
        (Some("b.com"), None, &["192.0.2.9"][..], ("Reject", true)),
        (Some("b.com"), None, &["198.51.100.8"][..], ("Proxy", true)),
        (
            Some("b.com"),
            None,
            &["192.0.2.9", "2001:db8::1"][..],
            ("Aliyun", true),
        ),
        (
            Some("b.com"),
            None,
            &["203.0.113.4", "192.0.2.9"][..],
            ("Reject", true),
        ),
    ];
    for (host, ip, answers, (action, resolved)) in expected_routes {
        assert_eq!(
            route_with_dns(&config, host, ip, answers),
            (action.to_string(), resolved),
            "{host:?} {ip:?} {answers:?}"
        );
    }
}

#[test]
fn resolves_against_all_address_families_without_masking_ipv6() {
    let project = Project::new();
    let config = project.compile("", "10.0.0.0/8, Direct\n::/80, Reject\n*, Proxy");
    assert_eq!(
        route_with_dns(&config, Some("b.com"), None, &["::1", "::ffff:10.0.0.1"]),
        ("Reject".into(), true)
    );
    assert_eq!(
        route_with_dns(&config, Some("b.com"), None, &["::ffff:10.0.0.1"]),
        ("Direct".into(), true)
    );
}

fn route_with_dns(
    config: &Value,
    host: Option<&str>,
    ip: Option<&str>,
    answers: &[&str],
) -> (String, bool) {
    let route = &config["route"];
    let mut matched_ips: Vec<_> = ip.map(|ip| ip.parse().unwrap()).into_iter().collect();
    let mut resolved = false;
    for rule in route["rules"].as_array().unwrap() {
        if !matches_output_ips(rule, host, &matched_ips) {
            continue;
        }
        match rule["action"].as_str().unwrap() {
            "resolve" => {
                assert!(matched_ips.is_empty());
                resolved = true;
                matched_ips = answers
                    .iter()
                    .map(|answer| answer.parse().unwrap())
                    .collect();
            }
            "reject" => return ("Reject".into(), resolved),
            "route" => return (rule["outbound"].as_str().unwrap().into(), resolved),
            action => panic!("{action}"),
        }
    }
    (route["final"].as_str().unwrap().into(), resolved)
}

#[test]
fn omits_dns_when_ip_rules_cannot_change_the_fallback() {
    let project = Project::new();
    let config = project.compile(
        "",
        "a.com, Reject\n203.0.113.0/24, Proxy\nRuleSet, PrivateIP, Proxy\n*, Proxy",
    );
    let rules = config["route"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["action"], "reject");
    assert_eq!(
        route_with_dns(&config, Some("b.com"), None, &["203.0.113.4"]),
        ("Proxy".into(), false)
    );
}

#[test]
fn ruleset_priority_breaks_ties_without_overriding_more_specific_rules() {
    let project = Project::new();
    project.write(
        "ads.json",
        r#"{"version":5,"rules":[{"domain_suffix":"byteadverts.com","ip_cidr":"10.0.0.0/8"}]}"#,
    );
    project.write("cn.json", r#"{"version":5,"rules":[{"domain_suffix":"byteadverts.com","domain":"api.byteadverts.com","ip_cidr":["10.0.0.0/8","10.2.0.0/16"]}]}"#);
    let imports = "ruleset ads = file(\"ads.json\")\nruleset cn = file(\"cn.json\")";
    let ads = "RuleSet, ads, Reject, 100";
    let cn = "RuleSet, cn, Direct";
    let another_cn = "RuleSet, cn, Aliyun, 40000";
    let output = project.compile(imports, &format!("{cn}\n{ads}\n{another_cn}\n*, Proxy"));
    assert_eq!(
        output,
        project.compile(imports, &format!("{ads}\n{another_cn}\n{cn}\n*, Proxy"))
    );
    assert_eq!(
        output_match(&output, Some("byteadverts.com"), None),
        "Reject"
    );
    assert_eq!(
        output_match(&output, Some("x.byteadverts.com"), None),
        "Reject"
    );
    assert_eq!(
        output_match(&output, Some("api.byteadverts.com"), None),
        "Direct"
    );
    assert_eq!(
        output_match(&output, None, Some("10.1.0.1".parse().unwrap())),
        "Reject"
    );
    assert_eq!(
        output_match(&output, None, Some("10.2.0.1".parse().unwrap())),
        "Direct"
    );
}

#[test]
fn reports_both_ruleset_actions_and_the_tied_priority() {
    let project = Project::new();
    let source = r#"{"version":5,"rules":[{"domain_suffix":"byteadverts.com"}]}"#;
    project.write("ads.json", source);
    project.write("cn.json", source);
    let imports = "ruleset ads = file(\"ads.json\")\nruleset cn = file(\"cn.json\")";
    let result = project.run(
        imports,
        "RuleSet, ads, Reject\nRuleSet, cn, Direct, 32766\n*, Proxy",
    );
    assert!(!result.status.success());
    let report = String::from_utf8_lossy(&result.stderr);
    for expected in [
        "conflict",
        "byteadverts.com",
        "including subdomains",
        "RuleSet ads",
        "RuleSet cn",
        "Reject",
        "Direct",
        "priority=32766",
        "ads.json:rules[0]",
        "cn.json:rules[0]",
    ] {
        assert!(report.contains(expected), "missing {expected:?}: {report}");
    }
    let higher = project.compile(
        imports,
        "RuleSet, cn, Direct\nRuleSet, ads, Reject\nRuleSet, cn, Aliyun, 5\n*, Proxy",
    );
    assert_eq!(
        output_match(&higher, Some("byteadverts.com"), None),
        "Aliyun"
    );
    project.error(imports, "RuleSet, ads, Reject, high\n*, Proxy", "priority");
    project.error("", "Domain, example.com, Proxy, 1\n*, Proxy", "expected");
}

#[test]
fn base_rules_run_before_generated_rules_when_requested() {
    let project = Project::new();
    let base_path = project.0.path().join("base.json");
    let compiled_path = project.0.path().join("compiled.json");
    let mut base: Value = serde_json::from_slice(&fs::read(&base_path).unwrap()).unwrap();
    let native = json!([
        {"port": [53], "action": "hijack-dns"},
        {"action": "sniff"}
    ]);
    base["route"] = json!({"rules": native, "final": "Aliyun", "auto_detect_interface": true});
    project.write("base.json", &base.to_string());
    let table = "blocked.example, Reject\n203.0.113.0/24, Direct\n*, Proxy";

    project.error("", table, "--base-rules-first");
    assert!(
        !project
            .run_with("", table, &["--base-rules-first", "--replace-route"])
            .status
            .success()
    );

    let result = project.run_with("", table, &["--base-rules-first"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let preserved: Value = serde_json::from_slice(&fs::read(&compiled_path).unwrap()).unwrap();
    let preserved_rules = preserved["route"]["rules"].as_array().unwrap();
    assert_eq!(&preserved_rules[..2], native.as_array().unwrap());
    assert_eq!(preserved["route"]["final"], "Proxy");
    assert_eq!(preserved["route"]["auto_detect_interface"], true);
    if let Some(binary) = std::env::var_os("SING_BOX") {
        let checked = Command::new(binary)
            .current_dir(project.0.path())
            .args(["check", "-c", "compiled.json"])
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    let result = project.run_with("", table, &["--replace-route"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let replaced: Value = serde_json::from_slice(&fs::read(&compiled_path).unwrap()).unwrap();
    assert_eq!(
        preserved_rules[2..],
        replaced["route"]["rules"].as_array().unwrap()[..]
    );
}

#[test]
fn compiles_route_and_dns_with_independent_targets_and_priorities() {
    let project = Project::new();
    project.write("base.json", r#"{
        "outbounds":[{"type":"direct","tag":"Direct"},{"type":"direct","tag":"Proxy"}],
        "route":{"default_domain_resolver":"local-dns"},
        "dns":{"servers":[{"type":"udp","tag":"local-dns","server":"192.0.2.53"},{"type":"udp","tag":"remote-dns","server":"198.51.100.53"}],
               "rules":[{"domain":["old.example"],"action":"route","server":"local-dns"}],"final":"local-dns","disable_cache":true}
    }"#);
    project.write("mixed.json", r#"{"version":5,"rules":[{"domain_suffix":"example.com","domain":"api.example.com","ip_cidr":"192.0.2.0/24"}]}"#);
    project.write(
        "ads.json",
        r#"{"version":5,"rules":[{"domain_suffix":"example.com"}]}"#,
    );
    project.write(
        "ips.json",
        r#"{"version":5,"rules":[{"ip_cidr":"192.0.2.0/24"}]}"#,
    );
    project.write(
        "new.rules",
        r#"
ruleset mixed = file("mixed.json")
ruleset ads = file("ads.json")
ruleset ips = file("ips.json")
outbounds {
    Direct
    Proxy
}
dns-server {
    local-dns
    remote-dns
}
route {
    RuleSet, mixed, Direct
    RuleSet, ads, Reject, 100
    *, Proxy
}
dns {
    RuleSet, mixed, local-dns
    RuleSet, ads, Reject, -9223372036854775808
    RuleSet, ips, remote-dns
    RuleSet, PrivateIP, remote-dns
    *, remote-dns
}
"#,
    );
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_sing-rules"))
            .current_dir(project.0.path())
            .args([
                "compile",
                "new.rules",
                "--base",
                "base.json",
                "-o",
                "compiled.json",
            ])
            .output()
            .unwrap()
    };
    let output = run();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("ips") && stderr.contains("PrivateIP"),
        "{stderr}"
    );
    let config: Value =
        serde_json::from_slice(&fs::read(project.0.path().join("compiled.json")).unwrap()).unwrap();
    assert_eq!(config["route"]["final"], "Proxy");
    assert_eq!(config["dns"]["final"], "remote-dns");
    assert_eq!(config["dns"]["disable_cache"], true);
    assert_eq!(config["dns"]["servers"].as_array().unwrap().len(), 2);
    assert!(
        config["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule.get("ip_cidr").is_some())
    );
    let dns = config["dns"]["rules"].as_array().unwrap();
    assert_eq!(dns.len(), 2);
    assert_eq!(dns[0]["domain"][0], "api.example.com");
    assert_eq!(dns[0]["server"], "local-dns");
    assert_eq!(dns[1]["action"], "reject");
    assert!(
        dns.iter()
            .all(|rule| rule.get("ip_cidr").is_none() && rule.get("outbound").is_none())
    );
    if let Some(binary) = std::env::var_os("SING_BOX") {
        let checked = Command::new(binary)
            .current_dir(project.0.path())
            .args(["check", "-c", "compiled.json"])
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    let input = fs::read_to_string(project.0.path().join("new.rules")).unwrap();
    for (old, new, expected) in [
        (
            "*, remote-dns",
            "192.0.2.1, local-dns\n*, remote-dns",
            "IP rules",
        ),
        ("*, remote-dns", "*, Reject", "DNS fallback"),
        (
            "    remote-dns\n}",
            "    missing-dns\n}",
            "undeclared DNS server",
        ),
        (
            "-9223372036854775808",
            "9223372036854775808",
            "signed 64-bit",
        ),
    ] {
        project.write("new.rules", &input.replace(old, new));
        let output = run();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains(expected),
            "{stderr}"
        );
    }

    project.write("new.rules", input.split("\ndns {").next().unwrap());
    assert!(run().status.success());
    let config: Value =
        serde_json::from_slice(&fs::read(project.0.path().join("compiled.json")).unwrap()).unwrap();
    let base: Value =
        serde_json::from_slice(&fs::read(project.0.path().join("base.json")).unwrap()).unwrap();
    assert_eq!(config["dns"], base["dns"]);
}
