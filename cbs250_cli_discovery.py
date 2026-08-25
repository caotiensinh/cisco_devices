#!/usr/bin/env python3
"""Cisco CBS250/CBS350 safe CLI help-tree discovery over SSH."""
from __future__ import annotations
import argparse, getpass, json, os, re, socket, sys, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import paramiko
except ImportError:
    print('Install: python -m pip install "paramiko>=3.4"', file=sys.stderr)
    raise SystemExit(2)

ANSI = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
HELP = re.compile(r"^\s+(\S+)(?:\s{2,}|\t+)(.*\S)?\s*$")
RISK = {
    "show":"read_only", "dir":"read_only", "pwd":"read_only", "more":"read_only",
    "help":"read_only", "terminal":"session_only", "ping":"diagnostic",
    "traceroute":"diagnostic", "configure":"mode_entry", "reload":"destructive",
    "delete":"destructive", "rmdir":"destructive", "clear":"state_changing",
    "copy":"state_changing", "write":"state_changing", "set":"state_changing",
    "no":"state_changing", "boot":"state_changing", "crypto":"state_changing",
    "dot1x":"state_changing", "system":"state_changing",
}

def clean(s: str) -> str:
    s = ANSI.sub("", s).replace("\x00", "")
    out=[]
    for ch in s:
        if ch == "\b":
            if out and out[-1] not in "\r\n": out.pop()
        else: out.append(ch)
    return "".join(out).replace("\r\n","\n").replace("\r","\n")

def keyword(tok: str) -> bool:
    if not tok or tok == "<cr>" or tok.startswith(("<","[","{")) or tok.isupper(): return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:/-]*", tok))

class Crawler:
    def __init__(self, a, password: str):
        self.a=a; self.password=password; self.client=None; self.shell=None; self.prompt=""
        self.nodes=0; self.visited=set(); self.errors=[]; self.transcript=[]

    def log(self, name: str, raw: str):
        self.transcript.append(f"\n===== {datetime.now(timezone.utc).isoformat()} | {name} =====\n{clean(raw)}\n")

    def connect(self):
        sock=socket.create_connection((self.a.host,self.a.port),timeout=10)
        t=paramiko.Transport(sock)
        try:
            sec=t.get_security_options()
            if "ssh-rsa" not in sec.key_types: sec.key_types=tuple(sec.key_types)+("ssh-rsa",)
            t.start_client(timeout=10)
            key=t.get_remote_server_key()
            self.transcript.append(f"\n===== SSH NEGOTIATION =====\nhost_key={key.get_name()}\nbits={key.get_bits()}\n")
            p_err=None
            try: t.auth_password(self.a.username,self.password,fallback=False)
            except paramiko.AuthenticationException as e: p_err=e
            if not t.is_authenticated():
                prompts=[]
                def handler(_title,_instructions,questions):
                    ans=[]
                    for q,_echo in questions:
                        prompts.append(q[:160]); ans.append(self.password if "password" in q.lower() or len(questions)==1 else "")
                    return ans
                try: t.auth_interactive(self.a.username,handler)
                except paramiko.BadAuthenticationType as e:
                    raise RuntimeError(f"Authentication failed; allowed methods={getattr(e,'allowed_types',[])}") from e
                except paramiko.AuthenticationException as e:
                    raise RuntimeError(f"Authentication failed; prompts={prompts!r}; password={p_err}; interactive={e}") from e
            if not t.is_authenticated(): raise RuntimeError("SSH authentication not established")
            c=paramiko.SSHClient(); c._transport=t; self.client=c
            self.shell=c.invoke_shell(term="vt100",width=240,height=1000); self.shell.settimeout(.25)
            self.log("initial",self.read(8)); self.send("\r"); raw=self.read(2); self.log("prompt",raw)
            self.prompt=self.get_prompt(raw)
            if not self.prompt: raise RuntimeError("CLI prompt not detected")
        except Exception:
            if not t.is_authenticated(): t.close()
            raise

    def close(self):
        for obj in (self.shell,self.client):
            if obj:
                try: obj.close()
                except Exception: pass

    def send(self,s):
        assert self.shell is not None; self.shell.send(s)

    def read(self,max_wait=5.0,quiet=.45):
        assert self.shell is not None
        chunks=[]; start=last=time.monotonic()
        while time.monotonic()-start < max_wait:
            got=False
            try:
                while self.shell.recv_ready():
                    b=self.shell.recv(65535)
                    if not b: break
                    chunks.append(b.decode("utf-8",errors="replace")); last=time.monotonic(); got=True
            except socket.timeout: pass
            if chunks and time.monotonic()-last >= quiet: break
            if not got: time.sleep(.03)
        return "".join(chunks)

    @staticmethod
    def get_prompt(raw):
        xs=[x.strip() for x in clean(raw).splitlines() if x.strip()]
        xs=[x for x in xs if x.endswith(("#",">")) and len(x)<=160]
        return xs[-1] if xs else ""

    def sync(self):
        self.send("\x03"); self.log("sync-ctrl-c",self.read(1.2)); self.send("\r")
        raw=self.read(1.2); self.log("sync-enter",raw); p=self.get_prompt(raw)
        if p: self.prompt=p

    def exec_safe(self,cmd):
        self.sync(); self.send(cmd+"\r"); raw=self.read(8,.3); self.log("EXEC "+cmd,raw)
        p=self.get_prompt(raw)
        if p: self.prompt=p
        return clean(raw)

    def parse_help(self,raw,prefix):
        query="?" if not prefix else prefix.rstrip()+" ?"; result=[]; seen=set()
        for line in clean(raw).splitlines():
            s=line.strip()
            if not s or s==query or s.endswith(query) or (self.prompt and s.startswith(self.prompt)): continue
            m=HELP.match(line)
            if not m: continue
            tok=m.group(1).strip()
            if tok in seen: continue
            seen.add(tok); desc=(m.group(2) or "").strip()
            kind="terminal" if tok=="<cr>" else ("keyword" if keyword(tok) else "placeholder")
            root=(prefix.split()[0] if prefix else tok).lower()
            result.append({"token":tok,"description":desc,"kind":kind,"risk":RISK.get(root,"unknown")})
        return result

    def help(self,mode,prefix):
        key=(mode,prefix.strip())
        if key in self.visited: return []
        self.visited.add(key); self.sync(); q="?" if not prefix.strip() else prefix.rstrip()+" ?"
        self.send(q)  # no Enter: context help only
        raw=self.read(4); self.log(f"HELP [{mode}] {q}",raw); self.send("\x03"); self.log("cancel",self.read(1.2))
        txt=clean(raw)
        if any(x in txt for x in ("Command too long","Unrecognized command","Invalid input")):
            self.errors.append({"mode":mode,"prefix":prefix,"response":txt[-1000:]})
        time.sleep(max(0,self.a.delay)); return self.parse_help(raw,prefix)

    def crawl(self,mode,prefix="",depth=0) -> dict[str,Any]:
        if depth>self.a.max_depth: return {"_meta":{"truncated":True,"reason":"max_depth"}}
        if self.nodes>=self.a.max_nodes: return {"_meta":{"truncated":True,"reason":"max_nodes"}}
        tree={}
        for item in self.help(mode,prefix):
            self.nodes+=1; tok=item.pop("token"); node={**item,"children":{}}; tree[tok]=node
            if self.nodes>=self.a.max_nodes:
                node["children"]={"_meta":{"truncated":True,"reason":"max_nodes"}}; break
            if node["kind"]=="keyword" and depth<self.a.max_depth:
                node["children"]=self.crawl(mode,tok if not prefix else f"{prefix} {tok}",depth+1)
        return tree

def args():
    p=argparse.ArgumentParser(description="Safe Cisco CBS250/CBS350 CLI capability discovery")
    p.add_argument("--host",required=True); p.add_argument("--username",default="admin"); p.add_argument("--port",type=int,default=22)
    p.add_argument("--max-depth",type=int,default=5); p.add_argument("--max-nodes",type=int,default=1500); p.add_argument("--delay",type=float,default=.08)
    p.add_argument("--no-config-mode",action="store_true"); p.add_argument("--output-dir",default=""); p.add_argument("--password-env",default="CBS_PASSWORD")
    return p.parse_args()

def main():
    a=args(); pw=os.getenv(a.password_env) or getpass.getpass(f"SSH password for {a.username}@{a.host}: ")
    stamp=datetime.now().strftime("%Y%m%d_%H%M%S"); out=Path(a.output_dir).expanduser() if a.output_dir else Path.home()/"Downloads"/f"CBS250_CLI_Discovery_{stamp}"
    out.mkdir(parents=True,exist_ok=True); c=Crawler(a,pw)
    doc={"schema_version":1,"generated_at_utc":datetime.now(timezone.utc).isoformat(),"device":{"host":a.host,"port":a.port,"username":a.username},
         "safety":{"discovered_commands_executed":False,"help_enter":False,"ctrl_c_after_help":True,
                   "allowlisted_commands":["terminal datadump","show version","show system","configure terminal","configure","end"]},"modes":{},"crawler":{}}
    rc=0
    try:
        print(f"[+] Connecting to {a.host}:{a.port}"); c.connect(); print(f"[+] Prompt: {c.prompt}")
        try: c.exec_safe("terminal datadump")
        except Exception as e: c.errors.append({"mode":"exec","prefix":"terminal datadump","response":str(e)})
        inv={}
        for cmd in ("show version","show system"):
            try: inv[cmd]=c.exec_safe(cmd)
            except Exception as e: inv[cmd]="ERROR: "+str(e)
        print("[+] Crawling privileged EXEC"); doc["modes"]["privileged_exec"]={"prompt":c.prompt,"inventory":inv,"tree":c.crawl("privileged_exec")}
        if not a.no_config_mode:
            c.exec_safe("configure terminal")
            if "(config" not in c.prompt: c.exec_safe("configure")
            if "(config" in c.prompt:
                print("[+] Crawling global config"); doc["modes"]["global_config"]={"prompt":c.prompt,"tree":c.crawl("global_config")}; c.exec_safe("end")
            else: c.errors.append({"mode":"global_config","prefix":"","response":"Could not enter config mode"})
    except KeyboardInterrupt: print("[!] Interrupted"); rc=130
    except Exception as e: print(f"[!] ERROR: {e}",file=sys.stderr); c.errors.append({"mode":"runtime","prefix":"","response":str(e)}); rc=1
    finally: c.close()
    doc["crawler"]={"nodes_found":c.nodes,"errors":c.errors}
    (out/"cbs250_command_tree.json").write_text(json.dumps(doc,indent=2,ensure_ascii=False),encoding="utf-8")
    summary={"device":doc["device"],"generated_at_utc":doc["generated_at_utc"],"nodes_found":c.nodes,"errors":len(c.errors),
             "modes":{n:{"prompt":m.get("prompt",""),"top_level_commands":[k for k in m.get("tree",{}) if k!="_meta"]} for n,m in doc["modes"].items()}}
    (out/"cbs250_capability_summary.json").write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding="utf-8")
    (out/"cbs250_raw_transcript.txt").write_text("".join(c.transcript),encoding="utf-8")
    print(f"[+] Output: {out}\n[+] Nodes found: {c.nodes}\n[+] Errors: {len(c.errors)}"); return rc

if __name__=="__main__": raise SystemExit(main())
