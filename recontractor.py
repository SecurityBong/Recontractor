import os
import subprocess
import shutil
import sys
import platform
import json
import urllib.request
import urllib.error
import ssl
import re
import threading
import time
import venv
import signal
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURATION ---
VERSION = "1.0"
AUTHOR = "Rahul A.K.A SecurityBong"
DESC = "Automated WAF Detection & Reconnaissance Suite For Sensitive Data"
TIMEOUT = 10
THREADS = 50 

CMD_PATHS = { "katana": "", "gau": "", "httpx": "", "nuclei": "" }

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

if platform.system() == "Windows": os.system('color')

def log(msg, type="INFO"):
    t = datetime.now().strftime("%H:%M:%S")
    if type == "STEP": print(f"\n{Colors.BLUE}{Colors.BOLD} >>> [{t}] {msg}{Colors.RESET}")
    elif type == "TOOL": print(f"{Colors.CYAN}[TOOL] Running: {msg}{Colors.RESET}")
    elif type == "PLUS": print(f"{Colors.GREEN}[PLUS RESULT] {msg}{Colors.RESET}")
    elif type == "CORE": print(f"{Colors.MAGENTA}[CORE EXTRACTION] {msg}{Colors.RESET}")
    elif type == "WAF": print(f"{Colors.MAGENTA}{Colors.BOLD}[WAF DETECTED] {msg}{Colors.RESET}")
    elif type == "ERROR": print(f"{Colors.RED}[!] {msg}{Colors.RESET}")
    elif type == "STATUS": print(f"{Colors.YELLOW}[STATUS] {msg}{Colors.RESET}")
    elif type == "SUCCESS": print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    else: print(f"[{t}] ... {msg}")

def signal_handler(sig, frame):
    print(f"\n\n{Colors.RED}{Colors.BOLD}[!] PAUSE DETECTED.{Colors.RESET}")
    try:
        choice = input(f"{Colors.YELLOW}Do you really want to exit? (y/n): {Colors.RESET}").strip().lower()
        if choice == 'y': sys.exit(0)
        else: print(f"{Colors.GREEN}[+] Resuming...{Colors.RESET}")
    except: sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def ensure_virtual_env():
    is_venv = (sys.prefix != sys.base_prefix)
    if not is_venv and platform.system() == "Linux":
        if not os.path.exists("recon_env"):
            try: venv.create("recon_env", with_pip=True)
            except: pass
        python_bin = os.path.join(os.getcwd(), "recon_env", "bin", "python3")
        if os.path.exists(python_bin): os.execv(python_bin, [python_bin] + sys.argv)

def get_go_bin():
    try:
        output = subprocess.check_output(["go", "env", "GOPATH"], text=True).strip()
        if output: return os.path.join(output, "bin")
    except: pass
    return os.path.join(os.path.expanduser("~"), "go", "bin")

def setup_tools():
    print(f"\n{Colors.BOLD}--- [ SYSTEM PRE-FLIGHT CHECK ] ---{Colors.RESET}")
    go_bin = get_go_bin()
    if go_bin not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + go_bin
        
    tools_repo = {
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "gau": "github.com/lc/gau/v2/cmd/gau@latest",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    }
    for tool, repo in tools_repo.items():
        found_path = None
        potential_paths = [os.path.join(go_bin, tool), shutil.which(tool), f"/usr/local/bin/{tool}", f"/usr/bin/{tool}"]
        for p in potential_paths:
            if p and os.path.exists(p):
                if tool == "httpx":
                    try:
                        res = subprocess.run([p, "-version"], capture_output=True, text=True, timeout=2)
                        if "projectdiscovery" in res.stdout.lower() or "projectdiscovery" in res.stderr.lower():
                            found_path = p; break
                    except: continue 
                else: found_path = p; break
        
        if found_path:
            CMD_PATHS[tool] = found_path
            print(f" {Colors.GREEN}[FOUND]{Colors.RESET}   {tool.ljust(8)} : {found_path}")
        else:
            print(f" {Colors.RED}[MISSING]{Colors.RESET} {tool.ljust(8)} : Installing...")
            try:
                subprocess.run(["go", "install", repo], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                p = os.path.join(go_bin, tool)
                if os.path.exists(p):
                    CMD_PATHS[tool] = p
                    print(f" {Colors.GREEN}[INSTALLED]{Colors.RESET} {tool.ljust(6)} : {p}")
            except: pass
    print(f"{Colors.BOLD}---------------------------------------{Colors.RESET}")

def run_tool_with_status(cmd, tool_name, output_file=None):
    outfile = None
    try:
        if output_file:
            outfile = open(output_file, "a")
            stdout_dest = outfile
        else: stdout_dest = subprocess.PIPE
        process = subprocess.Popen(cmd, stdout=stdout_dest, stderr=subprocess.PIPE, text=True)
        def monitor(p, name, out_f):
            delay = 30
            while p.poll() is None:
                time.sleep(delay)
                if p.poll() is None:
                    count = 0
                    if out_f and os.path.exists(out_f):
                        try:
                            with open(out_f, 'r', errors='ignore') as f: count = sum(1 for _ in f)
                        except: pass
                    log(f"{name} working... Found {count} items. (Next update in {delay+15}s)", "STATUS")
                    delay += 15
        t = threading.Thread(target=monitor, args=(process, tool_name, output_file))
        t.daemon = True; t.start(); process.wait()
        return True
    except: return False
    finally:
        if outfile: outfile.close()

def native_request(url, payload=None):
    target = url
    if payload:
        char = "&" if "?" in target else "?"
        target += f"{char}waf_test={urllib.parse.quote(payload)}"
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return {"code": r.getcode(), "headers": str(r.info()).lower()}
    except urllib.error.HTTPError as e: return {"code": e.code, "headers": str(e.headers).lower()}
    except: return None

def check_alive_python(urls_file, alive_file):
    log(f"Using Internal Engine ({THREADS} Threads)...", "STATUS")
    try:
        with open(urls_file, 'r') as f: urls = [l.strip() for l in f if l.strip() and l.startswith("http")]
    except: return 0
    total = len(urls); unique_alive = set(); counter = 0
    def check_url(u):
        res = native_request(u)
        if res and res['code'] in [200, 301, 302, 403, 401]: return u
        return None
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = {ex.submit(check_url, u): u for u in urls}
        for fut in as_completed(futs):
            counter += 1
            if counter % 100 == 0:
                sys.stdout.write(f"\r{Colors.YELLOW}[STATUS] Checked {counter} / {total} URLs...{Colors.RESET}"); sys.stdout.flush()
            res = fut.result()
            if res: unique_alive.add(res)
    with open(alive_file, 'w') as f:
        for u in unique_alive: f.write(u + "\n")
    return len(unique_alive)

def run_recon(target):
    domain = urlparse(target).netloc
    workspace = f"recon_{domain.replace('.', '_')}"
    os.makedirs(workspace, exist_ok=True)
    log(f"Initiating Recon (Workspace: {workspace})", "STEP")
    raw_file, alive_file = os.path.join(workspace, "raw_urls.txt"), os.path.join(workspace, "alive.txt")

    if CMD_PATHS["katana"]:
        log(f"{CMD_PATHS['katana']} (Crawling)", "TOOL")
        run_tool_with_status([CMD_PATHS["katana"], "-u", target, "-d", "3", "-jc", "-silent"], "Katana", raw_file)
    if CMD_PATHS["gau"]:
        log(f"{CMD_PATHS['gau']} (Archiving)", "TOOL")
        run_tool_with_status([CMD_PATHS["gau"], domain, "--threads", "10"], "Gau", raw_file)

    log("Deduplicating fetched URLs...", "INFO")
    if os.path.exists(raw_file):
        with open(raw_file, 'r') as f: lines = f.readlines()
        unique = set(l.strip() for l in lines if l.strip() and l.startswith("http"))
        with open(raw_file, 'w') as f: f.write('\n'.join(unique))
    else: log("No URLs found.", "ERROR"); sys.exit(0)

    log("Filtering for ALIVE endpoints...", "TOOL")
    alive_count = 0
    if CMD_PATHS["httpx"]:
        run_tool_with_status([CMD_PATHS["httpx"], "-l", raw_file, "-mc", "200,301,302,403,401", "-o", alive_file, "-silent"], "Httpx", alive_file)
        if os.path.exists(alive_file):
            with open(alive_file, 'r') as f: alive_count = sum(1 for _ in f)
    if alive_count == 0: alive_count = check_alive_python(raw_file, alive_file)
    if alive_count == 0: log("0 Alive endpoints found. Verify target availability.", "ERROR"); sys.exit(0)
    log(f"Found {alive_count} Alive endpoints.", "SUCCESS")

    log("Smart Grep: Searching for Sensitive Exposure...", "STEP")
    ext_pattern = re.compile(r"\.(zip|rar|tar|gz|config|log|bak|backup|java|old|xlsx|json|pdf|doc|docx|pptx|csv|htaccess|7z)$", re.IGNORECASE)
    secret_pattern = re.compile(
        r"(?i)(?:(?:access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|"
        r"alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|"
        r"aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\.googlemaps AIza|apidocs|apikey|"
        r"apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|"
