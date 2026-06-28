from flask import Flask, jsonify, request, Response, stream_with_context
import requests as req
import re
import math
import zipfile
import io
import os
import json
import docker
import tarfile
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

app = Flask(__name__)

# Near the top of app.py, after imports
def docker_is_available():
    try:
        client = docker.from_env(timeout=2)
        client.ping()
        return True
    except Exception:
        return False

DOCKER_AVAILABLE = docker_is_available()
print(f"DOCKER AVAILABLE: {DOCKER_AVAILABLE}")

# ─────────────────────────────────────
# FILE TIER CLASSIFICATION
# ─────────────────────────────────────
SCAN_EXTENSIONS = [
    ".py", ".js", ".ts", ".bat", ".cmd", ".sh", ".ps1",
    ".vbs", ".php", ".rb", ".java", ".c", ".cpp", ".go",
    ".rs", ".pl", ".lua", ".ino"
]
FLAG_ONLY_EXTENSIONS = [
    ".exe", ".jar", ".msi", ".scr", ".dll", ".com", ".apk",
    ".elf", ".bin", ".out", ".so"
]
MACRO_RISK_EXTENSIONS = [".docm", ".xlsm", ".pptm"]
ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z", ".tar", ".gz"]
SKIP_EXTENSIONS = [
    ".json", ".yaml", ".yml", ".txt", ".md", ".png", ".jpg",
    ".jpeg", ".gif", ".svg", ".ico", ".lock", ".gitignore"
]

# ─────────────────────────────────────
# URL PARSER
# ─────────────────────────────────────
def parse_github_url(url):
    try:
        parts = url.strip().split("github.com/")[1].split("/")
        owner = parts[0]
        repo = parts[1]
        if "blob" in parts:
            idx = parts.index("blob")
            path = "/".join(parts[idx + 2:])
        elif "tree" in parts:
            idx = parts.index("tree")
            path = "/".join(parts[idx + 2:])
        elif "raw" in parts:
            idx = parts.index("raw")
            path = "/".join(parts[idx + 2:])
        else:
            path = ""
        return owner, repo, path
    except Exception:
        return None, None, None

# ─────────────────────────────────────
# GITHUB API
# ─────────────────────────────────────
def get_files_from_github(owner, repo, path=""):
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    response = req.get(api_url, headers=GITHUB_HEADERS)
    if response.status_code != 200:
        return []
    items = response.json()
    if isinstance(items, dict):
        items = [items]
    files = []
    for item in items:
        if item["type"] == "file":
            files.append(item)
        elif item["type"] == "dir":
            files.extend(get_files_from_github(owner, repo, item["path"]))
    return files

def get_file_bytes(download_url):
    try:
        response = req.get(download_url, headers=GITHUB_HEADERS)
        return response.content
    except Exception:
        return b""

# ─────────────────────────────────────
# ENGINE 1 — REGEX SCANNER
# ─────────────────────────────────────
MALICIOUS_PATTERNS = [
    (r"discord\.com/api/webhooks/", "Discord Webhook detected — used for silent data exfiltration to attacker-controlled channels"),
    (r"t\.me/|telegram\.me/", "Telegram C2 endpoint — attacker using Telegram as command and control channel"),
    (r"socket\.connect\s*\(", "Raw TCP socket connection — classic reverse shell initiation pattern"),
    (r"subprocess\.Popen|os\.system|os\.popen", "Shell command execution via subprocess — can run arbitrary system commands"),
    (r"powershell.*WebRequest|powershell.*DownloadFile", "PowerShell file dropper — downloads and executes secondary payload"),
    (r"urllib\.request\.urlretrieve|requests\.get.*\.exe", "Downloads executable from external URL — dropper behavior"),
    (r"exec\s*\(\s*base64|eval\s*\(\s*base64", "Base64-encoded payload execution — obfuscation technique to hide malicious code"),
    (r"__import__\s*\(\s*['\"]os['\"]", "Dynamic OS module import — used to hide system access from static scanners"),
    (r"keylog|keystroke|GetAsyncKeyState", "Keylogger API usage — captures keystrokes including passwords and credentials"),
    (r"encrypt.*file|os\.walk.*encrypt", "File encryption loop — ransomware behavior pattern"),
    (r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory", "Windows process injection APIs — injects code into running processes"),
    (r"reg add|reg\.exe.*HKEY|schtasks", "Persistence mechanism — modifies registry or schedules tasks to survive reboot"),
]

def regex_scan(content, filename):
    findings = []
    seen = set()
    for pattern, description in MALICIOUS_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            key = (filename, description)
            if key not in seen:
                seen.add(key)
                # Find the actual line containing the match
                line_context = ""
                for i, line in enumerate(content.splitlines()):
                    if re.search(pattern, line, re.IGNORECASE):
                        line_context = f"Line {i+1}: {line.strip()[:100]}"
                        break
                findings.append({
                    "file": filename,
                    "type": "REGEX",
                    "severity": "HIGH",
                    "description": description,
                    "context": line_context,
                    "engine": "Engine 1 — Regex Pattern Scanner"
                })
    return findings

# ─────────────────────────────────────
# ENGINE 2 — SHANNON ENTROPY SCANNER
# ─────────────────────────────────────
def calculate_entropy(text):
    if not text:
        return 0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    entropy = 0
    length = len(text)
    for count in frequency.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy

RISKY_CONTEXT_KEYWORDS = [
    "exec", "eval", "decode", "os.system", "subprocess",
    "powershell", "base64", "socket", "webhook"
]

def entropy_scan(content, filename):
    findings = []
    string_matches = re.findall(r'["\']([^"\']{20,})["\']', content)
    for string in string_matches:
        entropy = calculate_entropy(string)
        if entropy > 4.5:
            context_window = content[
                max(0, content.find(string) - 100):content.find(string) + 100
            ].lower()
            is_risky_context = any(
                keyword in context_window for keyword in RISKY_CONTEXT_KEYWORDS
            )
            nearby_keyword = next(
                (kw for kw in RISKY_CONTEXT_KEYWORDS if kw in context_window), None
            )
            description = (
                f"High entropy string (score: {entropy:.2f}) found near '{nearby_keyword}' — "
                f"likely an encoded/encrypted payload about to be decoded and executed"
                if is_risky_context else
                f"High entropy string detected (score: {entropy:.2f}) — "
                f"could be an encryption key, encoded payload, or compressed data. "
                f"Sample: '{string[:40]}...'"
            )
            findings.append({
                "file": filename,
                "type": "ENTROPY",
                "severity": "HIGH" if is_risky_context else "MEDIUM",
                "description": description,
                "engine": "Engine 2 — Shannon Entropy Scanner"
            })
    return findings

# ─────────────────────────────────────
# ENGINE 3 — BEHAVIORAL SANDBOX
# ─────────────────────────────────────
DOCKER_IMAGE = "gitshield-sandbox:latest"
INTERPRETER_MAP = {
    ".py": "python3",
    ".sh": "bash",
    ".js": "node",
    ".rb": "ruby",
    ".pl": "perl",
}

BEHAVIOR_RULES = [
    (r'connect\(\d+,\s*\{sa_family=AF_INET.*sin_addr=inet_addr\("([\d.]+)"\)',
     "HIGH", "Attempted outbound network connection to {0} — possible data exfiltration or C2 beacon"),
    (r'socket\(AF_INET', "HIGH",
     "Opened raw TCP/IP socket — network communication attempted despite sandbox network isolation"),
    (r'execve\("[^"]*\b(bash|sh|powershell|cmd\.exe)\b',
     "HIGH", "Spawned interactive shell during execution — command chaining or privilege escalation"),
    (r'openat?\([^)]*"(/etc/passwd)"',
     "HIGH", "Read /etc/passwd — credential harvesting attempt"),
    (r'openat?\([^)]*"(/etc/shadow)"',
     "HIGH", "Read /etc/shadow — password hash theft attempt"),
    (r'openat?\([^)]*O_CREAT[^)]*"(/tmp/[^"]+)"',
     "MEDIUM", "Created file in /tmp — dropper may be writing secondary payload"),
    (r'clone\(|fork\(|vfork\(',
     "MEDIUM", "Spawned child process during execution — possible process injection or daemonization"),
    (r'ptrace\(',
     "HIGH", "Called ptrace() — anti-debugging technique or process injection attempt"),
    (r'chmod\([^)]*0?7[0-7][0-7]',
     "MEDIUM", "Changed file permissions to executable — self-modifying or dropper behavior"),
]

def make_tar_bytes(filename, file_bytes):
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(file_bytes)
        tar.addfile(info, io.BytesIO(file_bytes))
    tar_stream.seek(0)
    return tar_stream.read()

def parse_behavior(trace_output, rel_label):
    findings = []
    seen = set()
    for line in trace_output.splitlines():
        for pattern, severity, description in BEHAVIOR_RULES:
            match = re.search(pattern, line)
            if match:
                try:
                    desc = description.format(*match.groups())
                except (IndexError, KeyError):
                    desc = description
                key = (rel_label, desc)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "file": rel_label,
                        "type": "BEHAVIORAL",
                        "severity": severity,
                        "description": desc,
                        "engine": "Engine 3 — Behavioral Sandbox"
                    })
    return findings

def execute_in_sandbox(file_bytes, filename, rel_label):
    ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
    interpreter = INTERPRETER_MAP.get(ext)
    if not interpreter:
        return []

    if not DOCKER_AVAILABLE:
        return [{
            "file": rel_label, "type": "SANDBOX", "severity": "INFO",
            "description": "Sandbox execution unavailable in this environment (no Docker access). Static analysis (Regex, Entropy, AI) still applied.",
            "engine": "Engine 3 — Behavioral Sandbox"
        }]

    # Fast-fail if Docker isn't available at all (e.g. on Render)
    try:
        client = docker.from_env(timeout=2)  # 2 second connection timeout
        client.ping()
    except Exception:
        return [{
            "file": rel_label, "type": "SANDBOX", "severity": "INFO",
            "description": "Sandbox execution unavailable in this environment (no Docker access). Static analysis (Regex, Entropy, AI) still applied.",
            "engine": "Engine 3 — Behavioral Sandbox"
        }]

    container = None
    try:
        container = client.containers.create(
            DOCKER_IMAGE,
            command=["sleep", "60"],
            network_mode="none",
            mem_limit="64m",
            pids_limit=50,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
        )
        container.start()
        container.exec_run(["mkdir", "-p", "/code"])
        tar_bytes = make_tar_bytes(filename, file_bytes)
        container.put_archive("/code", tar_bytes)
        cmd = (
            f"strace -f -tt -s 200 -e trace=network,file,process "
            f"-o /tmp/trace.log timeout 8 {interpreter} /code/{filename}; "
            f"echo '---TRACE---'; cat /tmp/trace.log"
        )
        exec_result = container.exec_run(["sh", "-c", cmd])
        output = exec_result.output.decode("utf-8", errors="ignore")
        return parse_behavior(output, rel_label)
    except docker.errors.ImageNotFound:
        return [{
            "file": rel_label, "type": "SANDBOX", "severity": "INFO",
            "description": "Sandbox image not found — build it first.",
            "engine": "Engine 3 — Behavioral Sandbox"
        }]
    except Exception as e:
        return [{
            "file": rel_label, "type": "SANDBOX", "severity": "INFO",
            "description": f"Sandbox unavailable: {str(e)[:80]}",
            "engine": "Engine 3 — Behavioral Sandbox"
        }]
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
# ─────────────────────────────────────
# ENGINE 4 — AI ANALYSIS
# ─────────────────────────────────────
def extract_strings_from_bytes(file_bytes, min_length=5):
    pattern = rb"[\x20-\x7e]{%d,}" % min_length
    return [m.decode("ascii", errors="ignore") for m in re.findall(pattern, file_bytes)]

def extract_indicators(strings_list):
    text = "\n".join(strings_list)
    urls = re.findall(r'https?://[^\s"\'<>]+', text)
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    suspicious_keywords = [
        "cmd.exe", "powershell", "RegOpenKey", "CreateRemoteThread",
        "VirtualAlloc", "WinExec", "ShellExecute", "WriteProcessMemory",
        "keylog", "ransom", "bitcoin", "decrypt", "AES", "RC4",
        "discord.com/api/webhooks", "GetAsyncKeyState",
    ]
    found_keywords = [kw for kw in suspicious_keywords if kw.lower() in text.lower()]
    return {"urls": urls[:20], "ips": ips[:20], "keywords": found_keywords}

def ai_analyze_file(filename, file_bytes, file_type):
    if not GROQ_API_KEY:
        return {
            "file": filename, "type": "AI_ANALYSIS", "severity": "INFO",
            "description": "AI analysis unavailable — GROQ_API_KEY not configured.",
            "engine": "Engine 4 — AI Analysis"
        }

    strings_list = extract_strings_from_bytes(file_bytes)
    if not strings_list:
        return {
            "file": filename, "type": "AI_ANALYSIS", "severity": "HIGH",
            "description": f"No readable strings found in {filename} — file is likely packed or encrypted. This is a strong indicator of deliberate obfuscation.",
            "engine": "Engine 4 — AI Analysis"
        }

    indicators = extract_indicators(strings_list)
    sample_strings = "\n".join(strings_list[:300])

    prompt = f"""You are a malware analyst. Analyze this specific {file_type} file named '{filename}'.

Detected URLs: {indicators['urls']}
Detected IPs: {indicators['ips']}
Suspicious keywords found: {indicators['keywords']}

Sample extracted strings:
{sample_strings}

Provide a specific analysis for THIS file. Do not use generic descriptions.
Respond in this exact format:
VERDICT: [MALICIOUS | SUSPICIOUS | LIKELY_BENIGN]
CONFIDENCE: [HIGH | MEDIUM | LOW]
REASON: [Specific 2-3 sentence analysis of what THIS file does based on its actual strings and indicators]
"""

    try:
        response = req.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 300,
            },
            timeout=20,
        )
        data = response.json()
        ai_text = data["choices"][0]["message"]["content"]
    except Exception as e:
        return {
            "file": filename, "type": "AI_ANALYSIS", "severity": "INFO",
            "description": f"AI analysis failed: {str(e)[:100]}",
            "engine": "Engine 4 — AI Analysis"
        }

    verdict_match = re.search(r"VERDICT:\s*(\w+)", ai_text)
    confidence_match = re.search(r"CONFIDENCE:\s*(\w+)", ai_text)
    reason_match = re.search(r"REASON:\s*(.+)", ai_text, re.DOTALL)

    verdict = verdict_match.group(1) if verdict_match else "UNKNOWN"
    confidence = confidence_match.group(1) if confidence_match else "LOW"
    reason = reason_match.group(1).strip()[:300] if reason_match else ai_text[:200]

    severity = "HIGH" if verdict == "MALICIOUS" else (
        "MEDIUM" if verdict == "SUSPICIOUS" else "LOW"
    )

    return {
        "file": filename,
        "type": "AI_ANALYSIS",
        "severity": severity,
        "description": f"[{verdict} — {confidence} confidence] {reason}",
        "engine": "Engine 4 — AI Analysis"
    }

# ─────────────────────────────────────
# STREAMING SCAN ENDPOINT
# ─────────────────────────────────────
def sse_event(data):
    return f"data: {json.dumps(data)}\n\n"

@app.route("/scan-stream", methods=["GET"])
def scan_stream():
    url = request.args.get("url", "")

    def generate():
        if not url:
            yield sse_event({"type": "error", "message": "No URL provided"})
            return

        owner, repo, path = parse_github_url(url)
        if not owner or not repo:
            yield sse_event({"type": "error", "message": "Invalid GitHub URL"})
            return

        # Stage 1: Fetch files
        yield sse_event({"type": "stage", "stage": "fetch", "message": "Connecting to GitHub API..."})
        files = get_files_from_github(owner, repo, path)

        if not files:
            yield sse_event({"type": "error", "message": "No files found in repository or path"})
            return

        yield sse_event({
            "type": "stage", "stage": "fetch_done",
            "message": f"Found {len(files)} files in repository",
            "total_files": len(files)
        })

        all_findings = []
        scanned_files = []
        skipped_files = []

        for file in files:
            filename = file["name"]
            download_url = file.get("download_url")
            ext = "." + filename.split(".")[-1].lower() if "." in filename else ""

            if ext in SKIP_EXTENSIONS:
                skipped_files.append(filename)
                continue

            yield sse_event({
                "type": "file_start",
                "filename": filename,
                "file_type": ext
            })

            file_bytes = get_file_bytes(download_url) if download_url else b""
            content = file_bytes.decode("utf-8", errors="ignore") if ext in SCAN_EXTENSIONS else ""

            file_findings = []

            # Engine 1: Regex
            if ext in SCAN_EXTENSIONS and content:
                yield sse_event({
                    "type": "engine_start", "engine": "regex",
                    "message": f"Running Regex Engine on {filename}..."
                })
                regex_results = regex_scan(content, filename)
                file_findings.extend(regex_results)
                yield sse_event({
                    "type": "engine_done", "engine": "regex",
                    "message": f"Regex complete — {len(regex_results)} pattern(s) matched",
                    "findings": regex_results
                })

            # Engine 2: Entropy
            if ext in SCAN_EXTENSIONS and content:
                yield sse_event({
                    "type": "engine_start", "engine": "entropy",
                    "message": f"Running Entropy Engine on {filename}..."
                })
                entropy_results = entropy_scan(content, filename)
                file_findings.extend(entropy_results)
                yield sse_event({
                    "type": "engine_done", "engine": "entropy",
                    "message": f"Entropy complete — {len(entropy_results)} anomaly(s) found",
                    "findings": entropy_results
                })

            # Engine 3: Sandbox
            if ext in SCAN_EXTENSIONS and file_bytes:
                yield sse_event({
                    "type": "engine_start", "engine": "sandbox",
                    "message": f"Executing {filename} in isolated Docker container..."
                })
                sandbox_results = execute_in_sandbox(file_bytes, filename, filename)
                file_findings.extend(sandbox_results)
                yield sse_event({
                    "type": "engine_done", "engine": "sandbox",
                    "message": f"Sandbox complete — {len(sandbox_results)} behavior(s) detected",
                    "findings": sandbox_results
                })

            # Engine 4: AI
            if file_bytes:
                yield sse_event({
                    "type": "engine_start", "engine": "ai",
                    "message": f"Sending {filename} to AI analysis engine..."
                })
                file_type = (
                    "script" if ext in SCAN_EXTENSIONS else
                    "compiled binary" if ext in FLAG_ONLY_EXTENSIONS else
                    "archive" if ext in ARCHIVE_EXTENSIONS else
                    "macro document" if ext in MACRO_RISK_EXTENSIONS else
                    "unknown file"
                )
                ai_result = ai_analyze_file(filename, file_bytes, file_type)
                file_findings.append(ai_result)
                yield sse_event({
                    "type": "engine_done", "engine": "ai",
                    "message": f"AI analysis complete",
                    "findings": [ai_result]
                })

            # Archive handling
            if ext == ".zip" and file_bytes:
                yield sse_event({
                    "type": "engine_start", "engine": "archive",
                    "message": f"Extracting and scanning contents of {filename}..."
                })
                try:
                    zip_bytes = io.BytesIO(file_bytes)
                    with zipfile.ZipFile(zip_bytes) as archive:
                        for inner_name in archive.namelist():
                            if inner_name.endswith("/"):
                                continue
                            inner_ext = "." + inner_name.split(".")[-1].lower()
                            if inner_ext in SKIP_EXTENSIONS:
                                continue
                            inner_bytes = archive.read(inner_name)
                            inner_content = inner_bytes.decode("utf-8", errors="ignore") if inner_ext in SCAN_EXTENSIONS else ""
                            rel = f"{filename} → {inner_name}"
                            if inner_content:
                                file_findings.extend(regex_scan(inner_content, rel))
                                file_findings.extend(entropy_scan(inner_content, rel))
                            if inner_bytes:
                                file_findings.extend(execute_in_sandbox(inner_bytes, inner_name, rel))
                                file_findings.append(ai_analyze_file(inner_name, inner_bytes, "file inside archive"))
                    zip_bytes.close()
                    yield sse_event({
                        "type": "engine_done", "engine": "archive",
                        "message": f"Archive scan complete"
                    })
                except Exception as e:
                    yield sse_event({
                        "type": "engine_done", "engine": "archive",
                        "message": f"Could not open archive: {str(e)[:80]}"
                    })
            elif ext in ARCHIVE_EXTENSIONS and ext != ".zip":
                file_findings.append({
                    "file": filename, "type": "ARCHIVE", "severity": "HIGH",
                    "description": f"{ext.upper()} archive — cannot extract in memory. AI analysis applied to raw bytes.",
                    "engine": "Archive Inspector"
                })

            if ext in FLAG_ONLY_EXTENSIONS:
                file_findings.append({
                    "file": filename, "type": "BINARY", "severity": "HIGH",
                    "description": f"Compiled binary ({ext}) detected — not executed. AI string analysis applied.",
                    "engine": "File Type Classifier"
                })

            if ext in MACRO_RISK_EXTENSIONS:
                file_findings.append({
                    "file": filename, "type": "MACRO_RISK", "severity": "MEDIUM",
                    "description": f"Macro-enabled {ext} document — may contain auto-executing embedded code. AI string analysis applied.",
                    "engine": "File Type Classifier"
                })

            all_findings.extend(file_findings)
            scanned_files.append(filename)

            yield sse_event({
                "type": "file_done",
                "filename": filename,
                "file_findings_count": len(file_findings),
                "file_findings": file_findings
            })

        # Final verdict
        high_count = len([f for f in all_findings if f.get("severity") == "HIGH"])
        medium_count = len([f for f in all_findings if f.get("severity") == "MEDIUM"])

        if high_count > 0:
            status = "THREAT DETECTED"
        elif medium_count > 0:
            status = "REVIEW RECOMMENDED"
        else:
            status = "CLEAN"

        yield sse_event({
            "type": "complete",
            "owner": owner,
            "repo": repo,
            "path": path,
            "total_files_found": len(files),
            "scanned_files": scanned_files,
            "total_files_scanned": len(scanned_files),
            "skipped_files": skipped_files,
            "total_findings": len(all_findings),
            "status": status,
            "findings": all_findings,
        })

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )

# Keep old endpoint for backward compatibility
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    owner, repo, path = parse_github_url(url)
    if not owner or not repo:
        return jsonify({"error": "Invalid GitHub URL"}), 400
    files = get_files_from_github(owner, repo, path)
    if not files:
        return jsonify({"error": "No files found in repository or path"}), 404

    all_findings = []
    scanned_files = []

    for file in files:
        filename = file["name"]
        download_url = file.get("download_url")
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        if ext in SKIP_EXTENSIONS:
            continue
        file_bytes = get_file_bytes(download_url) if download_url else b""
        content = file_bytes.decode("utf-8", errors="ignore") if ext in SCAN_EXTENSIONS else ""
        if content:
            all_findings.extend(regex_scan(content, filename))
            all_findings.extend(entropy_scan(content, filename))
        if file_bytes and ext in SCAN_EXTENSIONS:
            all_findings.extend(execute_in_sandbox(file_bytes, filename, filename))
        if file_bytes:
            file_type = "script" if ext in SCAN_EXTENSIONS else "binary/archive"
            all_findings.append(ai_analyze_file(filename, file_bytes, file_type))
        scanned_files.append(filename)

    high_count = len([f for f in all_findings if f.get("severity") == "HIGH"])
    medium_count = len([f for f in all_findings if f.get("severity") == "MEDIUM"])
    status = "THREAT DETECTED" if high_count > 0 else ("REVIEW RECOMMENDED" if medium_count > 0 else "CLEAN")

    return jsonify({
        "owner": owner, "repo": repo, "path": path,
        "total_files_found": len(files),
        "scanned_files": scanned_files,
        "total_files_scanned": len(scanned_files),
        "total_findings": len(all_findings),
        "status": status,
        "findings": all_findings,
    })

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "GitShield Backend Running"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)