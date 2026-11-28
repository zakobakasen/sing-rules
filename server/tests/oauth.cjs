const {test} = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
test("the browser exchanges and rotates tokens at the IdP", async () => {
  const values = new Map(), posts = [];
  const p = {issuer:"https://idp.test",client:"client",epoch:1,token_endpoint:"https://idp.test/token",redirect:"https://app.test/"};
  const cx = vm.createContext({
    URLSearchParams, URL, Date, JSON, Error, console,
    location:{search:"",hash:"#code=once&state=s"}, history:{replaceState(){}},
    sessionStorage:{getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)},
    document:{getElementById:()=>({addEventListener(){},replaceChildren(){}}),querySelectorAll:()=>[]},
    fetch:async (url,opts)=>{
      if(url==="/api/provider")return Response.json(p);
      if(url.startsWith("/api/")){
        assert.ok(!opts.body.includes("refresh_token") && !opts.body.includes("once"));
        assert.match(opts.headers.Authorization,/^Bearer at/);
        return Response.json({});
      }
      assert.equal(url,p.token_endpoint);
      assert.equal(opts.credentials,"omit");
      const body=Object.fromEntries(opts.body);posts.push(body);
      if(body.grant_type==="authorization_code"){
        assert.equal(body.code_verifier,"verifier"); assert.equal(body.code,"once");
        return Response.json({token_type:"Bearer",access_token:"at1",refresh_token:"rt1",expires_in:0});
      }
      if(body.refresh_token==="rt1")return Response.json({token_type:"Bearer",access_token:"at2",refresh_token:"rt2",expires_in:0});
      return Response.json({error:"invalid_grant"},{status:400});
    }
  });
  const code=fs.readFileSync("server/src/app.js","utf8").split("run(async()=>{await callback();await home();})();")[0];
  vm.runInContext(code,cx);
  values.set("pending",JSON.stringify({state:"s",issuer:p.issuer,epoch:1,verifier:"verifier"}));
  await vm.runInContext("callback()",cx);
  // A reload resets JS globals while preserving sessionStorage.
  const next=vm.createContext({...cx});vm.runInContext(code,next);
  await vm.runInContext('Promise.all([api("me"),api("list")])',next);
  assert.equal(posts.length,2);
  await assert.rejects(vm.runInContext('api("me")',next));
  assert.equal(posts[2].refresh_token,"rt2");
  assert.ok(![...values.values()].some(v=>v.includes("rt2")));
});
