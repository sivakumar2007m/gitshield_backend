from ai_analysis import ai_analyze_file

result = ai_analyze_file(
    "fake_malware.exe",
    b"This program connects to http://evil-c2-server.com and calls CreateRemoteThread to inject code. powershell -enc base64payload",
    "compiled binary"
)
print(result)