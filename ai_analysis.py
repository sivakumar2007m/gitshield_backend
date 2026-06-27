import re
import os
import requests


groq_api_key = os.environ.get("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def extract_strings(file_bytes, min_length=5):
    """
    Extract printable ASCII strings from raw bytes — NEVER executes anything.
    Same technique as the Linux 'strings' command.
    """
    pattern = rb"[\x20-\x7e]{%d,}" % min_length
    matches = re.findall(pattern, file_bytes)
    return [m.decode("ascii", errors="ignore") for m in matches]


def extract_indicators(strings_list):
    """Pull out URLs, IPs, and suspicious keywords from extracted strings."""
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
    """
    Sends extracted strings/indicators (NOT the raw binary) to an LLM
    for risk assessment. No execution involved anywhere in this function.
    """
    if not GROQ_API_KEY:
        return {
            "file": filename, "type": "AI_ANALYSIS", "severity": "MEDIUM",
            "description": "AI analysis unavailable — GROQ_API_KEY not configured. Manual verification required."
        }

    strings_list = extract_strings(file_bytes)
    if not strings_list:
        return {
            "file": filename, "type": "AI_ANALYSIS", "severity": "HIGH",
            "description": "No readable strings found (likely packed/encrypted binary) — high obfuscation risk. Manual verification required."
        }

    indicators = extract_indicators(strings_list)
    sample_strings = "\n".join(strings_list[:300])

    prompt = f"""You are a malware analyst. Analyze this {file_type} file's extracted strings and indicators. Do NOT execute or simulate execution — only reason about what is shown.

Filename: {filename}
Detected URLs: {indicators['urls']}
Detected IPs: {indicators['ips']}
Suspicious keywords found: {indicators['keywords']}

Sample extracted strings (first 300):
{sample_strings}

Respond in this exact format:
VERDICT: [MALICIOUS | SUSPICIOUS | LIKELY_BENIGN]
CONFIDENCE: [HIGH | MEDIUM | LOW]
REASON: [one or two sentence explanation]
"""

    try:
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 200,
            },
            timeout=20,
        )
        data = response.json()
        ai_text = data["choices"][0]["message"]["content"]
    except Exception as e:
        return {
            "file": filename, "type": "AI_ANALYSIS", "severity": "MEDIUM",
            "description": f"AI analysis failed — manual verification required. ({str(e)[:150]})"
        }

    verdict_match = re.search(r"VERDICT:\s*(\w+)", ai_text)
    confidence_match = re.search(r"CONFIDENCE:\s*(\w+)", ai_text)
    reason_match = re.search(r"REASON:\s*(.+)", ai_text, re.DOTALL)

    verdict = verdict_match.group(1) if verdict_match else "UNKNOWN"
    confidence = confidence_match.group(1) if confidence_match else "LOW"
    reason = reason_match.group(1).strip() if reason_match else ai_text[:200]

    severity = "HIGH" if verdict == "MALICIOUS" else "MEDIUM"

    return {
        "file": filename, "type": "AI_ANALYSIS", "severity": severity,
        "description": f"AI Verdict: {verdict} (confidence: {confidence}) — {reason}",
    }