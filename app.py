from flask import Flask, jsonify, request
import requests
import re
import math
import zipfile
import io

app = Flask(__name__)

# ─────────────────────────────────────
# FILE TIER CLASSIFICATION
# ─────────────────────────────────────

SCAN_EXTENSIONS = [
    ".py", ".js", ".ts", ".bat", ".cmd", ".sh", ".ps1",
    ".vbs", ".php", ".rb", ".java", ".c", ".cpp", ".go",
    ".rs", ".pl", ".lua", ".ino"
]

FLAG_ONLY_EXTENSIONS = [
    ".exe", ".jar", ".msi", ".scr", ".dll", ".com", ".apk"
]

MACRO_RISK_EXTENSIONS = [
    ".docm", ".xlsm", ".pptm"
]

ARCHIVE_EXTENSIONS = [
    ".zip", ".rar", ".7z", ".tar", ".gz"
]

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
# GITHUB API — GET FILES (handles single file OR folder)
# ─────────────────────────────────────
def get_files_from_github(owner, repo, path=""):
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    response = requests.get(api_url)
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


def get_file_content(download_url):
    try:
        response = requests.get(download_url)
        return response.text
    except:
        return ""


# ─────────────────────────────────────
# ENGINE A — REGEX SCANNER
# ─────────────────────────────────────
MALICIOUS_PATTERNS = [
    (r"discord\.com/api/webhooks/", "Discord Webhook — Data exfiltration endpoint detected"),
    (r"t\.me/|telegram\.me/", "Telegram endpoint — Possible data exfiltration"),
    (r"socket\.connect\s*\(", "Raw socket connection — Possible reverse shell"),
    (r"subprocess\.Popen|os\.system|os\.popen", "System command execution detected"),
    (r"powershell.*WebRequest|powershell.*DownloadFile", "PowerShell dropper command detected"),
    (r"urllib\.request\.urlretrieve|requests\.get.*\.exe", "External executable download detected"),
    (r"exec\s*\(\s*base64|eval\s*\(\s*base64", "Base64 encoded execution detected"),
    (r"__import__\s*\(\s*['\"]os['\"]", "Hidden OS import detected"),
    (r"keylog|keystroke|GetAsyncKeyState", "Keylogger pattern detected"),
    (r"encrypt.*file|os\.walk.*encrypt", "Ransomware pattern detected"),
    (r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory", "Process injection pattern detected"),
    (r"reg add|reg\.exe.*HKEY|schtasks", "Persistence/registry manipulation detected"),
]

def regex_scan(content, filename):
    findings = []
    for pattern, description in MALICIOUS_PATTERNS:
        if re.findall(pattern, content, re.IGNORECASE):
            findings.append({
                "file": filename,
                "type": "REGEX",
                "severity": "HIGH",
                "description": description,
            })
    return findings


# ─────────────────────────────────────
# ENGINE B — SHANNON ENTROPY SCANNER
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
            context_window = content[max(0, content.find(string) - 100):content.find(string) + 100].lower()
            is_risky_context = any(keyword in context_window for keyword in RISKY_CONTEXT_KEYWORDS)

            findings.append({
                "file": filename,
                "type": "ENTROPY",
                "severity": "HIGH" if is_risky_context else "MEDIUM",
                "description": (
                    f"High entropy string detected (score: {entropy:.2f}) — "
                    + ("Found near suspicious execution context" if is_risky_context
                       else "Possible obfuscated data (low confidence, verify manually)")
                ),
                "sample": string[:50] + "..." if len(string) > 50 else string,
            })
    return findings


# ─────────────────────────────────────
# ZIP ARCHIVE — IN-MEMORY INSPECTION
# ─────────────────────────────────────
def scan_zip_in_memory(download_url, zip_filename):
    findings = []
    scanned = []

    try:
        response = requests.get(download_url)
        zip_bytes = io.BytesIO(response.content)  # RAM only, never saved to disk

        with zipfile.ZipFile(zip_bytes) as archive:
            for inner_name in archive.namelist():
                inner_ext = "." + inner_name.split(".")[-1].lower() if "." in inner_name else ""

                if inner_ext in SKIP_EXTENSIONS:
                    continue

                if inner_ext in FLAG_ONLY_EXTENSIONS:
                    findings.append({
                        "file": f"{zip_filename} → {inner_name}",
                        "type": "BINARY",
                        "severity": "MEDIUM",
                        "description": "Executable found inside archive — cannot text-scan. Manual review recommended.",
                    })
                    continue

                if inner_ext in SCAN_EXTENSIONS:
                    try:
                        with archive.open(inner_name) as f:
                            content = f.read().decode(errors="ignore")
                        scanned.append(f"{zip_filename} → {inner_name}")
                        findings.extend(regex_scan(content, f"{zip_filename} → {inner_name}"))
                        findings.extend(entropy_scan(content, f"{zip_filename} → {inner_name}"))
                    except Exception:
                        continue

        zip_bytes.close()  # Explicitly discard from memory

    except Exception as e:
        findings.append({
            "file": zip_filename,
            "type": "ARCHIVE",
            "severity": "MEDIUM",
            "description": f"Could not inspect archive contents: {str(e)}",
        })

    return findings, scanned


# ─────────────────────────────────────
# MAIN SCAN ENDPOINT
# ─────────────────────────────────────
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
    flagged_binaries = []
    skipped_files = []

    for file in files:
        filename = file["name"]
        download_url = file.get("download_url")
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""

        if ext in SKIP_EXTENSIONS:
            skipped_files.append(filename)
            continue

        if ext in ARCHIVE_EXTENSIONS and download_url:
            zip_findings, zip_scanned = scan_zip_in_memory(download_url, filename)
            all_findings.extend(zip_findings)
            scanned_files.extend(zip_scanned)
            continue

        if ext in FLAG_ONLY_EXTENSIONS:
            flagged_binaries.append(filename)
            all_findings.append({
                "file": filename,
                "type": "BINARY",
                "severity": "MEDIUM",
                "description": "Executable/compiled file detected — cannot perform static text analysis. Manual review strongly recommended before running.",
            })
            continue

        if ext in MACRO_RISK_EXTENSIONS:
            all_findings.append({
                "file": filename,
                "type": "MACRO_RISK",
                "severity": "MEDIUM",
                "description": "Macro-enabled document detected — may contain auto-executing embedded code. Open with macros disabled.",
            })
            continue

        if ext in SCAN_EXTENSIONS and download_url:
            content = get_file_content(download_url)
            scanned_files.append(filename)
            all_findings.extend(regex_scan(content, filename))
            all_findings.extend(entropy_scan(content, filename))
        else:
            skipped_files.append(filename)

    high_severity_count = len([f for f in all_findings if f["severity"] == "HIGH"])
    total_files_found = len(files)

    if high_severity_count > 0:
        status = "THREAT DETECTED"
    elif all_findings:
        status = "REVIEW RECOMMENDED"
    else:
        status = "CLEAN"

    result = {
        "owner": owner,
        "repo": repo,
        "path": path,
        "total_files_found": total_files_found,
        "scanned_files": scanned_files,
        "total_files_scanned": len(scanned_files),
        "flagged_binaries": flagged_binaries,
        "skipped_files": skipped_files,
        "total_findings": len(all_findings),
        "status": status,
        "findings": all_findings,
    }

    return jsonify(result)


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "GitShield Backend Running"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)