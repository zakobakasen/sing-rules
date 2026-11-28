"""HTTP integration against a real binary, SQLite database and optional sing-box."""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from cryptography.x509.oid import NameOID

def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        return s.getsockname()[1]

class Idp:
    def __init__(self,directory):
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        tls=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        ca=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        now=datetime.now(timezone.utc)
        def cert(name,issuer,key,is_ca):
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
            return (x509.CertificateBuilder().subject_name(subject)
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,issuer)]))
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=is_ca,path_length=None),critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False)
                .sign(ca,hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        self.ca=directory/"ca.pem"
        self.ca.write_bytes(cert("Test CA","Test CA",ca,True))
        (directory/"cert.pem").write_bytes(cert("localhost","Test CA",tls,False))
        (directory/"key.pem").write_bytes(tls.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        idp=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def reply(self,value):
                data=json.dumps(value).encode()
                self.send_response(200);self.send_header("Content-Length",str(len(data)));self.send_header("Cache-Control","max-age=600");self.end_headers();self.wfile.write(data)
            def do_GET(self):
                if self.path=="/.well-known/oauth-authorization-server":
                    self.reply(dict(issuer=idp.url,jwks_uri=idp.url+"/keys",authorization_endpoint=idp.url+"/auth",token_endpoint=idp.url+"/token"))
                elif self.path=="/keys":
                    idp.key_reads+=1
                    n=idp.key.public_key().public_numbers().n
                    self.reply({"keys":[dict(kty="RSA",kid="key",alg="RS256",e="AQAB",n=b64(n.to_bytes((n.bit_length()+7)//8,"big")))]})
                else:self.send_error(404)
        self.key_reads=0
        self.server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        self.url="https://localhost:"+str(self.server.server_port)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(directory/"cert.pem",directory/"key.pem")
        self.server.socket=ctx.wrap_socket(self.server.socket,server_side=True)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
    def jwt(self,typ="at+jwt",**claims):
        now=int(time.time())
        payload=dict(iss=self.url,sub="new-user",aud="resource",client_id="client",iat=now,exp=now+300,jti="test")
        payload.update(claims)
        body=".".join(b64(json.dumps(x).encode()) for x in [dict(typ=typ,alg="RS256",kid="key"),payload])
        return body+"."+b64(self.key.sign(body.encode(),padding.PKCS1v15(),hashes.SHA256()))
    def close(self):
        self.server.shutdown();self.server.server_close()

@unittest.skipUnless(os.getenv("SING_RULES_SERVER"),"set SING_RULES_SERVER")
class Service(unittest.TestCase):
    def setUp(self):
        self.bin=os.environ["SING_RULES_SERVER"]
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.dir=Path(temp.name);self.db=self.dir/"test.db";self.port=free_port()
        self.origin="http://127.0.0.1:"+str(self.port)
        self.idp=Idp(self.dir);self.addCleanup(self.idp.close)
        self.password=subprocess.check_output([self.bin,"init","--db",self.db,"--listen",str(self.port)],text=True).strip()
        self.assertRegex(self.password,r"^[A-Za-z0-9]{43}$")
        self.proc=None
        self.start()
        self.addCleanup(self.stop)
        self.local="Local "+self.api("login",dict(password=self.password))["token"]
        self.settings=dict(public=self.origin,listen=str(self.port),issuer=self.idp.url,client="client",audience="resource",scope="",imports=[])
        self.api("settings",self.settings,self.local)
    def start(self):
        env={**os.environ,"SSL_CERT_FILE":str(self.idp.ca),"NO_PROXY":"localhost,127.0.0.1","no_proxy":"localhost,127.0.0.1"}
        self.proc=subprocess.Popen([self.bin,"serve","--db",self.db],env=env)
        for _ in range(120):
            try:
                with urllib.request.urlopen(self.origin,timeout=0.5): return
            except OSError: time.sleep(.05)
        self.fail("service startup failed")
    def stop(self):
        if self.proc and self.proc.poll() is None:self.proc.terminate();self.proc.wait(timeout=10)
    def api(self,op,v=None,auth="",status=200):
        r=urllib.request.Request(self.origin+"/api/"+op,json.dumps(v or {}).encode(),{"Content-Type":"application/json","Authorization":auth})
        try:
            with urllib.request.urlopen(r) as res:
                self.assertEqual(res.status,status);return json.load(res)
        except urllib.error.HTTPError as e:
            with e:
                reason=e.read().decode(); self.assertEqual(e.code,status,reason);return json.loads(reason)
    def test_auth(self):
        self.api("me",status=401)
        meta=self.api("provider")
        self.assertEqual(meta["token_endpoint"],self.idp.url+"/token")
        self.api("exchange",status=401)
        at=self.idp.jwt()
        guest="Bearer "+at
        me=self.api("me",auth=guest)
        self.assertEqual((me["role"],me["sub"]),("guest","new-user"))
        self.api("list",auth=guest,status=403)
        for patch in [dict(aud="wrong"),dict(client_id="wrong"),dict(iss="wrong"),dict(typ="JWT"),dict(exp=0),dict(nbf=int(time.time())+1000)]:
            error=self.api("me",auth="Bearer "+self.idp.jwt(**patch),status=401)
            field=next(iter(patch))
            self.assertEqual(error["field"],field)
            self.assertIn(str(patch[field]),error["actual"])
            self.assertIn(error["expected"],error["error"])
            self.assertEqual(error["code"],"token_expired" if field=="exp" else "invalid_token")
        for patch,field in [(dict(sub=""),"sub"),(dict(jti=""),"jti"),(dict(iat="yesterday"),"iat"),(dict(exp=None),"exp"),(dict(aud=["resource",123]),"aud")]:
            err=self.api("me",auth="Bearer "+self.idp.jwt(**patch),status=401)
            self.assertEqual(err["field"],field)
        header,payload,sig=at.split(".")
        for replacement,field in [(dict(alg="none",typ="at+jwt"),"alg"),(dict(alg="RS256",typ="at+jwt",kid="unknown"),"kid")]:
            token=b64(json.dumps(replacement).encode())+"."+payload+"."+sig
            self.assertEqual(self.api("me",auth="Bearer "+token,status=401)["field"],field)
        tampered=at.rsplit(".",1)[0]+"."+("A" if sig[0]!="A" else "B")+sig[1:]
        self.assertEqual(self.api("me",auth="Bearer "+tampered,status=401)["field"],"signature")
        self.assertEqual(self.idp.key_reads,1)
        self.api("purge-keys",auth=self.local)
        self.api("me",auth=guest)
        self.assertEqual(self.idp.key_reads,2)
        def role(sub,value):self.api("role",dict(sub=sub,issuer=self.idp.url,role=value),self.local)
        role("new-user","user")
        self.api("admin",auth=guest,status=403)
        other=self.api("config-new",dict(note="owned by admin"),self.local)
        self.api("config-save",dict(id=other,note="x"),guest,404)
        self.assertEqual(self.api("list",auth=guest)["configs"],[])
        self.api("password",dict(password=None),self.local,400)
        role("admin","admin")
        admin="Bearer "+self.idp.jwt(sub="admin")
        self.api("password",dict(password=None),admin)
        self.api("me",auth=self.local,status=401)
        self.api("login",dict(password=self.password),status=401)
        self.api("role",dict(sub="new-user",issuer=self.idp.url,role="guest"),admin)
        self.api("list",auth=guest,status=403)
    @unittest.skipUnless(hasattr(socket,"AF_UNIX") and os.name=="posix","Unix sockets")
    def test_unix_restart(self):
        try: socket.socket(socket.AF_UNIX,socket.SOCK_STREAM).close()
        except PermissionError:self.skipTest("runtime prohibits Unix sockets")
        sock=self.dir/"server.sock"
        self.api("settings",{**self.settings,"listen":"unix:"+str(sock)},self.local)
        self.stop()
        for _ in range(2):
            self.proc=subprocess.Popen([self.bin,"serve","--db",self.db])
            for attempt in range(100):
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    try:client.connect(str(sock))
                    except OSError:
                        time.sleep(.02)
                        continue
                    client.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    self.assertIn(b"200 OK",client.recv(512))
                    break
            else:self.fail("Unix listener unavailable")
            self.stop()

    def test_publication(self):
        create=lambda note:self.api("config-new",dict(note=note),self.local)
        first=create("first");second=create("second")
        token=self.api("link-new",dict(note="subscription"),self.local)
        self.assertRegex(token,r"^[a-zA-Z0-9._~-]{43}$")
        public=self.origin+"/s/"+token
        with self.assertRaises(urllib.error.HTTPError) as err:urllib.request.urlopen(public)
        self.assertEqual(err.exception.code,404)
        links=self.api("list",auth=self.local)["links"]; lid=links[0]["id"]
        sr="outbounds {\nDirect\n}\nroute {\n*.example.com, Reject\n10.0.0.0/8, Reject\n*, Direct\n}\n"
        self.api("config-save",dict(id=first,sr=sr,base=json.dumps({"outbounds":[{"type":"direct","tag":"Direct"}]})),self.local)
        self.stop();self.start()
        self.api("compile",dict(id=first),self.local)
        self.api("link-save",dict(id=lid,target=first),self.local)
        with urllib.request.urlopen(public) as res:
            self.assertEqual(res.url,public); cfg=json.load(res)
        sb=os.getenv("SING_BOX")
        matched=set()
        for entry in cfg["route"]["rule_set"]:
            self.assertEqual(entry["url"],self.origin+"/srs/"+entry["tag"]+".srs")
            with urllib.request.urlopen(entry["url"]) as res: data=res.read()
            self.assertEqual(data[:4],b"SRS\x02")
            if sb:
                f=self.dir/(entry["tag"]+".srs");f.write_bytes(data)
                subprocess.run([sb,"rule-set","decompile","-o",self.dir/"decompiled.json",f],check=True)
                for hostname in ["child.example.com","example.com","otherexample.com"]:
                    out=subprocess.run([sb,"rule-set","match","-f","binary",f,hostname],capture_output=True,check=True)
                    if b"match rules." in out.stdout+out.stderr: matched.add(hostname)
                entry.update(type="local",path=str(f));del entry["url"]
        if sb:
            self.assertEqual(matched,{"child.example.com"})
            f=self.dir/"compiled.json";f.write_text(json.dumps(cfg));subprocess.run([sb,"check","-c",f],check=True)
        self.api("config-save",dict(id=first,sr="bad"),self.local)
        self.api("compile",dict(id=first),self.local,400)
        with urllib.request.urlopen(public) as res:self.assertEqual(res.status,200)
        self.api("link-save",dict(id=lid,target=second),self.local)
        with self.assertRaises(urllib.error.HTTPError) as err:urllib.request.urlopen(public)
        self.assertEqual(err.exception.code,404)
