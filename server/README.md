# sing-rules-server

独立的 Rust 服务端。SQLite 保存监听地址、身份设置、角色、上传的源码、基础 JSON、编译结果、发布链接和 SRS 字节。WebUI 随二进制内置。

## 启动

```sh
sing-rules-server init --db rules.db --listen 8080
sing-rules-server serve --db rules.db
```

打开 http://127.0.0.1:8080 。初始化只接受新数据库。省略 `--password` 时，初始化命令打印一个 43 位大小写字母和数字组成的随机密码。也可以传入自己的初始密码。默认监听回环地址，可显式指定 `0.0.0.0:8080`。在 Unix 上可用 `--listen unix:/run/sing-rules/http.sock`，父目录需要存在。监听设置在下次启动时生效。

## 身份

先用管理员密码进入「服务设置」。公开访问地址填浏览器和订阅客户端均可访问的源（如 `https://rules.example.com`）。公网部署由反向代理提供 HTTPS。将这个源加上末尾的 `/` 登记为 IdP 的回调地址。WebUI 使用公共客户端、授权码和 PKCE S256，浏览器直接向 IdP 的 token endpoint 交换授权码和刷新令牌。请在 IdP 启用公共客户端的授权码及刷新授权，允许 WebUI 的 origin 跨域调用令牌端点，并按 IdP 要求设置获取 RT 的 scope。AT 和 RT 保存在当前标签页的 sessionStorage，刷新页面后继续使用。应用 API 只接收 AT。IdP 撤销 RT 后，下次刷新需要重新登录；已签发的 AT 在有效期内仍可通过本地验签。

在设置里填 issuer、client ID、资源标识和可选 scope。带资源标识的授权请求使用 RFC 8707 的 `resource` 参数。服务端按 issuer 发现公钥，同时验证访问令牌签名、类型、有效期、aud 和 client_id。首次通过 IdP 登录后，访客可以在「我的身份」复制自己的 sub。管理员在「身份授权」给当前 issuer 下的 sub 分配权限。可在另一个浏览器窗口验证 IdP 管理员已能进入「服务设置」，然后删除初始密码，所有密码会话随即失效。紧急轮换时，管理员可清除发现文档和公钥缓存。

## 编译和发布

1. 在「配置文件」新建空配置，填写备注，打开配置后分别上传或编辑 .sr 和基础 JSON，点击保存。文件可分别保存，再次打开时可继续编辑。
2. 「编译已保存的文件」保留基础 JSON 的已有路由规则并排在生成的规则前。成功后一次性发布配置与其 SRS。编译出错时，已有链接继续提供上一次成功版本。
3. 在「发布链接」填写备注，自选 43 位标识或留空随机生成。可用字符为大小写字母、数字和 `-._~`。创建后先选择指向的配置并保存。一个配置可以绑定多个链接，改绑或解除绑定即时生效。未绑定、未编译均返回 HTTP 404。
4. 客户端访问 `/s/<标识>` 直接取得 JSON。规则集使用 `/srs/<摘要>.srs`。摘要为 SRS **实际字节**的 BLAKE3-256，再用无填充 base64url 编码。摘要同时用作规则集 tag。

备注按所有者分别在配置、链接各自的列表内唯一。普通用户仅能访问自己的内容，管理员可管理全部。公开订阅链接是持有即可读取的凭据。服务端导入允许管理员登记的完整 HTTPS URL；请填写最终下载 URL。直接引用服务器文件系统的导入仅适用于原有单机编译器。服务端原生生成 SRS，导入已有第三方二进制 SRS 时沿用单机版解码路径，要求 PATH 中有 sing-box。JSON 规则集导入无需这个依赖。

## 从源码构建

```sh
cargo build --locked --release -p sing-rules-server
cargo test --locked --workspace
```

HTTP 集成测试使用 Python 的 cryptography 包。设置 SING_RULES_SERVER 指向构建的二进制，SING_BOX 指向 sing-box 后运行
`python -m unittest discover -s server/tests -p '*.py'`。
