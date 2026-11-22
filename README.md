# sing-rules

将按匹配范围决定优先级的路由表编译成 sing-box JSON。支持一张路由表，以及一张可选的 DNS 表。

```text
ruleset cn-ip = url("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.json")
ruleset cn = file("./rules/cn-domains.json")
ruleset ads = file("./rules/ads.json")

outbounds {
    Proxy
    Direct
    Aliyun
}

route {
    IP, 1.1.1.1/32, Proxy
    2001:db8::1, Direct
    a.com, Direct
    *.a.com, Aliyun
    RuleSet, cn, Aliyun
    RuleSet, cn-ip, Direct
    RuleSet, ads, Reject, 100
    RuleSet, PrivateIP, Direct
    *, Proxy
}

dns-server {
    local-dns
    remote-dns
}

dns {
    RuleSet, ads, Reject, 100
    RuleSet, cn, local-dns
    *.example.com, remote-dns
    *, remote-dns
}
```

## 编译

```sh
cargo run --locked -- compile routes.rules --base sing-box.json -o compiled.json
sing-box check -c compiled.json
```

基础配置提供入站、出站和 DNS 等配置。 `outbounds` 块声明表可以引用的出站标签，名称与基础配置的 `tag` 一致。 `Reject` 是内置动作。省略 `-o` 时输出到标准输出。基础配置已有 `route.rules` 时，使用 `--base-rules-first` 将它们按原顺序放在生成规则之前，或使用 `--replace-route` 替换它们。两项互斥。 `route.final` 由 DSL 的全局兜底决定，其他基础配置字段会保留。

例如，要先将 53 端口的请求交给 sing-box 的 DNS 模块，在基础配置中写入以下原生规则，并在编译时加 `--base-rules-first`。

```json
{
  "route": {
    "rules": [
      { "port": [53], "action": "hijack-dns" }
    ]
  }
}
```

## 语法和优先级

- 一行一个匹配项，格式为 `[类型,] 匹配内容, 出站`。可显式写 `IP`、`Domain`、`DomainSuffix`、`RuleSet` 或 `Any`。规则集写成 `RuleSet, 名称, 目标[, 优先级]`。
- 裸地址分别按 IPv4 `/32` 和 IPv6 `/128` 处理。同一前缀或域名范围的多个候选中，最高优先级的动作胜出。最高优先级相同但动作不同时会报冲突。
- `a.com` 精确匹配根域名，`*.a.com` 匹配任意深度的子域名。域名按 DNS 标签边界匹配，书写时可使用大写、根点和 IDNA 域名。
- 先匹配最具体的域名，再尝试已有的目标 IP。IP 阶段依次使用非 `/0` 的最长 CIDR、`PrivateIP`、对应 IP 家族的 `/0`，最后使用必填的全局 `*`。
- 当表里有可影响选路的 IP 条件时，只有域名且第一轮未命中的连接会执行 sing-box 的 `resolve`，随后只匹配 IP 条件。已有目标 IP 的连接在第一轮选定动作。解析使用 sing-box 的 DNS 配置，解析出错时由 sing-box 结束该连接。
- DNS 返回多个地址时，具体 CIDR 按原始前缀长度从长到短匹配任一地址。相同长度优先 `Reject`，其他动作按出站标签排序。若两族的 `/0` 都匹配，IPv4 的 `/0` 优先。
- `RuleSet, PrivateIP, Direct` 直接使用 sing-box 的 `ip_is_private`，继承运行版本对非公网地址的定义。

## DNS

`dns-server` 声明可在 `dns` 块中引用的服务器标签。它们必须存在于基础配置的 `dns.servers` 中。 `dns` 块生成 `dns.rules`，必填的 `*` 指向一个服务器并生成 `dns.final`。非兜底规则可用 `Reject`。

DNS 只匹配查询域名。导入 RuleSet 时，先剔除 IP 条目，再判断优先级和冲突。纯 IP 规则集和 `PrivateIP` 会在 DNS 表中警告并跳过。手写 IP 条目会报错。

出现 `dns` 块时，它替换基础配置的 `dns.rules` 和 `dns.final`，保留服务器定义和其他 DNS 设置。省略 `dns` 块时沿用基础配置的 DNS。 `--base-rules-first` 与 `--replace-route` 只作用于 `route.rules`。

旧版配置请将 `outbound` 改为 `outbounds`，将 `table default` 改为 `route`，将 `REJECT` 改为 `Reject`。第四列改用裸整数，并按数字越小越优先的规则重新选择数值。

## 规则集

用户定义的规则集名称匹配 `[A-Za-z0-9._~-]+`，区分大小写。 `file(...)` 的相对路径以 DSL 源文件所在目录为基准。 `url(...)` 在编译时下载源文件。

支持 sing-box JSON 规则集版本 1 至 5，以及可由本地 sing-box 反编译的 SRS 版本 2 至 5。使用 `--sing-box /path/to/sing-box` 可指定反编译程序。规则集中的目标域名、域名后缀、IP 和由这些条件构成的逻辑 OR 可以展开。遇到 `domain_regex`、`port` 等其他字段时，编译器向标准错误输出警告，并继续导入同一条规则里的目标域名、域名后缀和 IP。因此省略端口一类的限制后，保留的匹配项会适用于更广的流量。逻辑 AND 和取反会警告并跳过整条规则。支持字段的值格式错误或导入了带旧版后缀语义的 SRS 版本 1 时，编译会报错。导入项和手写规则共享优先级，输出使用内联条件。

规则集引用可加第四列，例如 `RuleSet, ads, Reject, 100`。优先级为有符号 64 位整数，数字越小越优先，省略时取 `32766`。普通表规则也使用 `32766`。优先级只用于解决完全相同的匹配范围。更具体的域名或 CIDR 仍先匹配，改变行顺序不会改变结果。

### 远程规则集缓存

`url(...)` 按 URL 缓存已成功解析的下载文件，24 小时内重复编译可直接复用。同一个 URL 用多个规则集名称引用时也共用缓存。缓存过期时重新下载，刷新失败会报错，旧文件仍保留。 `file(...)` 每次编译读取本地文件。

Windows 默认目录为 `%LOCALAPPDATA%/sing-rules/cache/rulesets`，macOS 为 `~/Library/Caches/sing-rules/rulesets`，Linux 为 `$XDG_CACHE_HOME/sing-rules/rulesets` 或 `~/.cache/sing-rules/rulesets`。使用 `--cache-dir <目录>` 指定其他路径，使用 `--refresh` 跳过缓存并重新下载。

## 测试

```sh
cargo test --locked
SING_BOX=/path/to/sing-box cargo test --locked
SING_BOX_RUNTIME=/path/to/sing-box cargo test --locked verifies_real_routing -- --ignored
```

`SING_BOX` 启用真实二进制的配置检查、匹配和 SRS 测试。 `SING_BOX_RUNTIME` 启用需要启动 sing-box 并监听本地端口的 SOCKS 连接测试。
