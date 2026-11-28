"""Exercise the embedded WebUI with the runner's installed Chrome."""
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.request import urlopen


from service import free_port

def federated_login(browser, origin):
    import base64
    import hashlib
    from urllib.parse import parse_qs, urlencode, urlsplit

    page = browser.new_page()
    idp = "https://identity.example"
    provider = dict(issuer=idp, epoch=1, client="web", audience="app", scope="",
                    redirect=origin+"/", endpoint=idp+"/authorize", token_endpoint=idp+"/token", fragment=True)
    flow = {}
    grants = []
    page.route(origin+"/api/provider", lambda r: r.fulfill(json=provider))
    def authorize(route):
        q = parse_qs(urlsplit(route.request.url).query)
        assert q["response_mode"] == ["fragment"]
        flow["challenge"] = q["code_challenge"][0]
        route.fulfill(status=302, headers={"Location":origin+"/#"+urlencode(dict(code="one-use-code",state=q["state"][0]))})
    def exchange(route):
        fields = parse_qs(route.request.post_data)
        grant = fields["grant_type"][0]
        grants.append(grant)
        headers = {"Access-Control-Allow-Origin": origin}
        assert "authorization" not in route.request.headers
        if grant == "authorization_code":
            verifier = fields["code_verifier"][0].encode()
            assert base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).decode().rstrip("=") == flow["challenge"]
            assert fields["code"] == ["one-use-code"]
            reply = dict(access_token="first-at", refresh_token="first-rt")
        elif fields["refresh_token"] == ["first-rt"]:
            reply = dict(access_token="second-at", refresh_token="second-rt")
        else:
            assert fields["refresh_token"] == ["second-rt"]
            route.fulfill(status=400, headers=headers, json={"error":"invalid_grant"})
            return
        route.fulfill(headers=headers, json={**reply,"token_type":"Bearer","expires_in":3600})
    def me(route):
        auth = route.request.headers["authorization"]
        if flow.get("bad_audience"):
            route.fulfill(status=401,json={"code":"invalid_token","field":"aud","actual":"other","expected":"app","error":"aud 实际值 other，预期 app"})
        elif flow.get("expired") == auth:
            route.fulfill(status=401, json={"error":"exp 已过期","code":"token_expired"})
        else:
            assert auth in ("Bearer first-at", "Bearer second-at")
            route.fulfill(json={"role":"guest","issuer":idp,"sub":"federated-sub"})
    page.route(idp+"/authorize*", authorize)
    page.route(idp+"/token", exchange)
    page.route(origin+"/api/me", me)
    page.goto(origin)
    page.locator("#idp").click()
    page.get_by_text("federated-sub",exact=True).wait_for()
    flow["expired"] = "Bearer first-at"
    page.reload()
    page.get_by_text("federated-sub",exact=True).wait_for()
    flow["expired"] = "Bearer second-at"
    page.reload()
    page.locator("#local").wait_for()
    page.get_by_text("exp 已过期；IdP 刷新失败：授权已过期或被 IdP 撤销，请重新登录 (invalid_grant)",exact=True).wait_for()
    assert grants == ["authorization_code", "refresh_token", "refresh_token"]
    flow["bad_audience"] = True
    page.locator("#idp").click()
    page.get_by_text("aud 实际值 other，预期 app",exact=True).wait_for()
    assert grants[-2:] == ["refresh_token","authorization_code"]
    page.close()

def main():
    from playwright.sync_api import sync_playwright
    binary = os.environ["SING_RULES_SERVER"]
    port = str(free_port())
    origin = "http://127.0.0.1:" + port
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "ui.db"
        password = subprocess.check_output([binary, "init", "--db", db, "--listen", port], text=True).strip()
        server = subprocess.Popen([binary, "serve", "--db", db])
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=os.environ["CHROME_BIN"])
                page = browser.new_page()
                page.goto(origin)
                page.locator("#local input").fill(password)
                page.locator("#local button").click()
                page.get_by_role("button", name="服务设置").click()
                page.locator("[name=public]").fill(origin)
                page.get_by_role("button", name="保存设置").click()
                page.get_by_text("设置已保存", exact=True).wait_for()
                page.get_by_role("button", name="配置文件").click()
                page.locator("#newconfig input").fill("test")
                page.locator("#newconfig button").click()
                page.locator("#sources summary").click()
                page.locator("[name=srText]").fill("outbounds {\nDirect\n}\nroute {\n*.example.com, Reject\n*, Direct\n}")
                page.locator("[name=baseText]").fill('{"outbounds":[{"type":"direct","tag":"Direct"}]}')
                page.locator("#sources button").click()
                page.get_by_text("已保存", exact=True).wait_for()
                page.reload()
                page.get_by_role("button", name="配置文件").click()
                page.get_by_role("button", name="打开配置").click()
                page.locator("#compile").click()
                page.get_by_text("编译完成，已绑定的链接现在提供本次结果").wait_for()
                page.get_by_role("button", name="发布链接").click()
                page.locator("#newlink [name=note]").fill("share")
                page.locator("#newlink button").click()
                page.locator("#linklist select").select_option(label="test")
                page.locator("#linklist button").click()
                page.get_by_text("链接已更新").wait_for()
                with urlopen(page.locator("#linklist p").inner_text()) as response:
                    assert response.status == 200
                federated_login(browser, origin)
                browser.close()
        finally:
            server.terminate()
            server.wait(timeout=10)

if __name__ == "__main__":
    main()
