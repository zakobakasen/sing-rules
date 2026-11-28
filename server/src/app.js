"use strict";
const $ = id => document.getElementById(id);
const fields = form => Object.fromEntries(new FormData(form));
let me, catalog, settings, editing, draft;
function node(tag, text) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  return el;
}
function notice(text) { $("message").textContent = text; }
function run(fn) {
  return async event => {
    event?.preventDefault();
    const button = event?.submitter ?? event?.currentTarget;
    if (button?.tagName === "BUTTON") button.disabled = true;
    notice("");
    try { await fn(); }
    catch (e) { notice(e.message); }
    finally { if (button?.tagName === "BUTTON") button.disabled = false; }
  };
}
const submit = (id, fn) => $(id).addEventListener("submit", run(fn));
const click = (id, fn) => $(id).addEventListener("click", run(fn));
function button(text, fn) { const b = node("button",text); b.type="button"; b.onclick=run(fn); return b; }
function section(id) {
  for (const s of document.querySelectorAll("main > section")) s.hidden = s.id !== id;
}
function federated() {
  return JSON.parse(sessionStorage.getItem("oauth") || "null");
}
function forgetLogin() {
  sessionStorage.removeItem("oauth");
  sessionStorage.removeItem("auth");
  $("nav").replaceChildren();
  section("login");
}
async function idpTokens(provider, grant, previousRefresh) {
  const response = await fetch(provider.token_endpoint, {
    method:"POST", credentials:"omit", redirect:"error", cache:"no-store", referrerPolicy:"no-referrer",
    body:new URLSearchParams({client_id:provider.client, ...grant})
  });
  const data = await response.json();
  if (!response.ok) {
    const reason = data.error_description || (data.error === "invalid_grant" ? "授权已过期或被 IdP 撤销，请重新登录" : "IdP 令牌请求失败");
    const error = new Error(data.error ? reason+" ("+data.error+")" : reason);
    error.oauth = data.error;
    throw error;
  }
  const refreshToken = data.refresh_token ?? previousRefresh;
  if (data.token_type?.toLowerCase() !== "bearer" || !data.access_token || !refreshToken)
    throw new Error("IdP 需要为此公共客户端签发 Bearer AT 和 RT，请检查授权范围和刷新设置");
  const expires = Number.isFinite(data.expires_in) ? Date.now()+1000*data.expires_in : null;
  return {provider, access:data.access_token, refresh:refreshToken, expires};
}
let refreshing;
async function renew(session) {
  if (!refreshing) {
    const original = sessionStorage.getItem("oauth");
    refreshing = idpTokens(session.provider, {grant_type:"refresh_token", refresh_token:session.refresh}, session.refresh)
      .then(next => {
        if (sessionStorage.getItem("oauth") !== original) throw new Error("登录状态已更改");
        sessionStorage.setItem("oauth", JSON.stringify(next));
        return next;
      }).catch(error => {
        if (error.oauth === "invalid_grant" && sessionStorage.getItem("oauth") === original) forgetLogin();
        throw error;
      }).finally(() => { refreshing = undefined; });
  }
  return refreshing;
}
async function api(op, data={}) {
  const protectedOp = !["provider","login"].includes(op);
  let session = protectedOp && federated();
  if (session && session.expires !== null && session.expires <= Date.now()) session = await renew(session);
  const send = (auth) => fetch("/api/"+op, {method:"POST", cache:"no-store",
    headers:auth ? {"Content-Type":"application/json",Authorization:auth} : {"Content-Type":"application/json"},
    body:JSON.stringify(data)});
  let response = await send(session ? "Bearer "+session.access : protectedOp && sessionStorage.getItem("auth"));
  const failure = response.status === 401 ? await response.clone().json().catch(()=>({})) : {};
  if (failure.code === "token_expired" && session) {
    const current = federated();
    if (current) {
      let next;
      try {next = current.access === session.access ? await renew(current) : current;}
      catch (error) {throw new Error(failure.error+"；IdP 刷新失败："+error.message);}
      response = await send("Bearer "+next.access);
    }
  }
  if (response.status === 401 && protectedOp) forgetLogin();
  const result = await response.json().catch(()=>({error:"HTTP "+response.status}));
  if (!response.ok) throw new Error(result.error);
  return result;
}
function base64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}
click("idp",async()=>{
  const p=await api("provider");
  if (!p) throw new Error("管理员尚未配置身份提供商");
  if (p.redirect!==location.origin+"/") throw new Error("请通过管理员设置的公开地址登录");
  const verifier=base64(crypto.getRandomValues(new Uint8Array(32)));
  const state=base64(crypto.getRandomValues(new Uint8Array(32)));
  const challenge=base64(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier)));
  sessionStorage.setItem("pending",JSON.stringify({state,verifier,epoch:p.epoch,issuer:p.issuer}));
  const url=new URL(p.endpoint);
  const params={response_type:"code",client_id:p.client_id??p.client,redirect_uri:p.redirect,resource:p.audience,
    state,code_challenge:challenge,code_challenge_method:"S256"};
  if(p.scope) params.scope=p.scope;
  if(p.fragment) params.response_mode="fragment";
  for(const [key,val] of Object.entries(params)) url.searchParams.set(key,val);
  location.assign(url);
});
async function callback() {
  const fragment=new URLSearchParams(location.hash.slice(1));
  const q=fragment.has("code") || fragment.has("error") ? fragment : new URLSearchParams(location.search);
  if(!q.has("code") && !q.has("error")) return;
  history.replaceState(null,"","/");
  const pending=JSON.parse(sessionStorage.getItem("pending")??"null");
  sessionStorage.removeItem("pending");
  if (!pending || !pending.state || pending.state!==q.get("state") || (q.has("iss")&&q.get("iss")!==pending.issuer))
    throw new Error("登录回调与当前请求不符，请重新登录");
  if(q.has("error")) throw new Error(q.get("error_description")||q.get("error"));
  const p=await api("provider");
  if (!p || p.issuer!==pending.issuer || p.epoch!==pending.epoch) throw new Error("身份提供商已更改，请重新登录");
  const session=await idpTokens(p,{grant_type:"authorization_code",code:q.get("code"),
    code_verifier:pending.verifier,redirect_uri:p.redirect});
  sessionStorage.removeItem("auth");
  sessionStorage.setItem("oauth",JSON.stringify(session));
}
submit("local",async()=>{
  const r=await api("login",fields($("local")));
  $("local").reset(); sessionStorage.removeItem("oauth"); sessionStorage.setItem("auth","Local "+r.token); await home();
});
async function logout() {
  try {if (sessionStorage.getItem("auth")?.startsWith("Local ")) await api("logout");}
  finally {forgetLogin(); location.replace("/");}
}
async function home() {
  if(!federated() && !sessionStorage.getItem("auth")){section("login");return;}
  me=await api("me");
  const nav=$("nav"); nav.replaceChildren(button("我的身份",()=>section("profile")));
  if(me.role!=="guest") nav.append(button("配置文件",async()=>{await refresh();section("configs");}),button("发布链接",async()=>{await refresh();section("links");}));
  if(me.role==="admin")nav.append(button("服务设置",async()=>{await loadSettings();section("admin");}));
  nav.append(button("退出",logout));
  const identity=$("identity"); identity.replaceChildren();
  const roles={admin:"管理员",user:"用户",guest:"访客"};
  for(const [label,val] of [["权限",roles[me.role]],["Issuer",me.issuer||"本地密码登录"],["Subject（sub）",me.sub??"本地管理员没有 IdP sub"]]){
    identity.append(node("dt",label),node("dd",val));
  }
  section("profile");
}
async function editConfig(c) {
  const source=await api("config-read",{id:c.id}); draft=source;
  editing=c.id; $("editor").hidden=false; $("editing").textContent=c.note;
  $("sources").reset(); $("sources").elements.note.value=source.note;
  for(const key of ["sr","base"]) $("sources").elements[key+"Text"].value=source[key]??""; $("editor").scrollIntoView();
}
async function refresh() {
  catalog=await api("list");
  $("configlist").replaceChildren(); $("linklist").replaceChildren();
  for(const c of catalog.configs){
    const row=node("div"); row.className="entry";
    row.append(node("strong",c.note),node("p",[c.sr?".sr 已保存":".sr 待上传",c.base?"JSON 已保存":"JSON 待上传",c.compiled?"已有编译结果":"待编译"].join(" · ")),button("打开配置",()=>editConfig(c)));
    $("configlist").append(row);
  }
  for(const l of catalog.links){
    const form=node("form");
    const note=node("input"); note.value=l.note;note.required=true;
    const target=node("select");target.append(new Option("未绑定",""));
    for(const c of catalog.configs.filter(c=>c.owner===l.owner)) target.append(new Option(c.note,c.id));
    target.value=l.target??"";
    for(const [name,input] of [["链接备注",note],["指向配置",target]]){
      const label=node("label",name);label.append(input);form.append(label);
    }
    form.append(node("p",(catalog.public||location.origin)+"/s/"+l.token),node("button","保存链接"));
    form.onsubmit=run(async()=>{await api("link-save",{id:l.id,note:note.value,target:target.value?Number(target.value):null});await refresh();notice("链接已更新");});
    $("linklist").append(form);
  }
}
submit("newconfig",async()=>{
  const id=await api("config-new",fields($("newconfig"))); $("newconfig").reset();
  await refresh();await editConfig(catalog.configs.find(c=>c.id===id));
});
submit("sources",async()=>{
  const form=$("sources");const data={id:editing,revision:draft.revision,note:form.elements.note.value};
  for(const key of ["sr","base"]) {const file=form.elements[key].files[0]; if(file)data[key]=await file.text(); else if(form.elements[key+"Text"].value!==(draft[key]??"")) data[key]=form.elements[key+"Text"].value;}
  await api("config-save",data);await refresh();await editConfig(catalog.configs.find(c=>c.id===editing));notice("已保存");
});
click("compile",async()=>{await api("compile",{id:editing});await refresh();notice("编译完成，已绑定的链接现在提供本次结果");});
submit("newlink",async()=>{await api("link-new",fields($("newlink")));$("newlink").reset();await refresh();notice("已创建，请选择指向的配置");});
async function loadSettings(){
  const r=await api("admin"); settings=r.settings;
  for(const [k,v] of Object.entries({...settings,listen:r.listen}))$("settings").elements[k].value=Array.isArray(v)?v.join("\n"):v;
  $("roles").replaceChildren(...r.roles.map(r=>node("p",r.issuer+" · "+r.sub+" · "+r.role)));
  $("pwstate").textContent=r.has_password?"管理员密码已启用":"管理员密码已删除";
}
submit("settings",async()=>{
  const v=fields($("settings"));v.imports=v.imports.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  await api("settings",v);await loadSettings();notice("设置已保存");
});
submit("role",async()=>{await api("role",{issuer:settings.issuer,...fields($("role"))});await loadSettings();notice("权限已更新");});
async function password(value) {
  await api("password",{password:value});$("password").reset();
  if(sessionStorage.getItem("auth")?.startsWith("Local ")){sessionStorage.removeItem("auth");location.replace("/");}
  else{await loadSettings();notice("管理员密码已更新");}
}
submit("password",()=>password(fields($("password")).password));
click("removepass",async()=>{if(confirm("删除管理员密码并注销所有密码登录会话？"))await password(null);});
click("purge",async()=>{await api("purge-keys");notice("已清除身份发现文档及公钥缓存");});
run(async()=>{await callback();await home();})();
