"""Exercise the embedded WebUI with the runner's installed Chrome."""
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.request import urlopen


from service import free_port

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
                browser.close()
        finally:
            server.terminate()
            server.wait(timeout=10)

if __name__ == "__main__":
    main()
