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
        self.write("routes.rules", &format!(
            "outbound {{\n Proxy\n Direct\n Aliyun\n}}\n{declarations}\ntable default {{\n{table}\n}}\n"
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
            ])
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
        "10.1.0.0/16, REJECT",
        "10.1.2.0/24, Direct",
        "172.16.1.0/24, REJECT",
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
    project.write(
        "cn.json",
        r#"{"version":4,"rules":[{"ip_cidr":["10.0.0.0/8"],"port":[80]}]}"#,
    );
    project.error(
        r#"ruleset cn = file("cn.json")"#,
        "RuleSet, cn, Proxy\n*, Direct",
        "port",
    );
}

#[test]
fn distinguishes_family_defaults_and_global_reject() {
    let project = Project::new();
    let config = project.compile("", "0.0.0.0/0, Direct\n::/0, Aliyun\n*, REJECT");
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
        api.a.com, REJECT
        *, Proxy
    ",
    );
    for (host, target) in [
        ("a.com", "Direct"),
        ("b.a.com", "Aliyun"),
        ("x.b.a.com", "Aliyun"),
        ("api.a.com", "REJECT"),
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
    let targets = ["Direct", "Aliyun", "Proxy", "REJECT"];

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
        Some(rule) if rule["action"] == "reject" => "REJECT",
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
    project.write("routes.rules", "outbound {\nDirect\nProxy\n}\nruleset sites = file(\"source.srs\")\ntable default {\nRuleSet, sites, Direct\n*, Proxy\n}\n");
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
        RuleSet, PrivateIP, REJECT
        a.com, Direct
        *.a.com, REJECT
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
        RuleSet, PrivateIP, REJECT
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

#[test]
fn downloads_and_expands_a_url_ruleset() {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
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
        let payload = r#"{"version":2,"rules":[{"ip_cidr":["203.0.113.0/24"]}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        )
        .unwrap();
    });
    let project = Project::new();
    let config = project.compile(
        &format!("ruleset c.n~1 = url(\"http://{addr}/ip.json\")"),
        "RuleSet, c.n~1, Aliyun\n*, Proxy",
    );
    server.join().unwrap();
    assert_eq!(
        output_match(&config, None, Some("203.0.113.4".parse().unwrap())),
        "Aliyun"
    );
}

#[test]
fn resolves_only_domain_misses_and_rechecks_only_ip_rules() {
    let project = Project::new();
    let config = project.compile(
        "",
        "
        a.com, REJECT
        203.0.113.0/24, Direct
        192.0.2.0/24, REJECT
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
        (Some("a.com"), None, &[][..], ("REJECT", false)),
        (
            Some("a.com"),
            Some("203.0.113.4"),
            &[][..],
            ("REJECT", false),
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
        (Some("b.com"), None, &["192.0.2.9"][..], ("REJECT", true)),
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
            ("REJECT", true),
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
    let config = project.compile("", "10.0.0.0/8, Direct\n::/80, REJECT\n*, Proxy");
    assert_eq!(
        route_with_dns(&config, Some("b.com"), None, &["::1", "::ffff:10.0.0.1"]),
        ("REJECT".into(), true)
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
            "reject" => return ("REJECT".into(), resolved),
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
        "a.com, REJECT\n203.0.113.0/24, Proxy\nRuleSet, PrivateIP, Proxy\n*, Proxy",
    );
    let rules = config["route"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["action"], "reject");
    assert_eq!(
        route_with_dns(&config, Some("b.com"), None, &["203.0.113.4"]),
        ("Proxy".into(), false)
    );
}
