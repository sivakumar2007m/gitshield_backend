import docker
import tarfile
import io
import os
import re
import zipfile
import requests

DOCKER_IMAGE = "gitshield-sandbox:latest"

INTERPRETER_MAP = {
    ".py": "python3",
    ".sh": "bash",
    ".js": "node",
    ".pl": "perl",
    ".rb": "ruby",
}

BINARY_EXTENSIONS = [".exe", ".elf", ".bin", ".out", ".dll", ".so", ".apk", ".jar", ".msi", ".scr", ".com"]


def make_tar_bytes(filename, file_bytes):
    """Build an in-memory tar archive containing the file — never touches disk."""
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(file_bytes)
        tar.addfile(info, io.BytesIO(file_bytes))
    tar_stream.seek(0)
    return tar_stream.read()


def execute_in_memory(file_bytes, filename, rel_label):
    """
    Runs untrusted bytes inside a container WITHOUT ever writing them
    to the host filesystem. Bytes are injected via the Docker API
    directly into the container's internal storage.
    """
    ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
    interpreter = INTERPRETER_MAP.get(ext)

    if not interpreter:
        if ext in BINARY_EXTENSIONS:
            return [{
                "file": rel_label, "type": "BINARY", "severity": "HIGH",
                "description": "Compiled binary detected — not executed. Manual verification required."
            }]
        return []

    try:
        client = docker.from_env()
    except Exception as e:
        import traceback
        traceback.print_exc()
        return [{
            "file": rel_label, "type": "SANDBOX", "severity": "HIGH",
            "description": f"Sandbox execution error — flagged for manual review. ({str(e)[:300]})"
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
        container.exec_run(["mkdir", "-p", "/code"])   # ← ADD THIS LINE

        # Inject the file directly via Docker API — host disk never touched
        tar_bytes = make_tar_bytes(filename, file_bytes)
        container.put_archive("/code", tar_bytes)
        trace_file = "/tmp/trace.log"
        cmd = (
            f"strace -f -tt -s 200 -e trace=network,file,process "
            f"-o {trace_file} timeout 8 {interpreter} /code/{filename}; "
            f"echo '---TRACE---'; cat {trace_file}"
        )

        exec_result = container.exec_run(["sh", "-c", cmd])
        output = exec_result.output.decode("utf-8", errors="ignore")

    except docker.errors.ImageNotFound:
        return [{
            "file": rel_label, "type": "SANDBOX", "severity": "HIGH",
            "description": f"Sandbox image '{DOCKER_IMAGE}' not found. Build it first — see Dockerfile.sandbox."
        }]
    except Exception as e:
        return [{
            "file": rel_label, "type": "SANDBOX", "severity": "HIGH",
            "description": f"Sandbox execution error — flagged for manual review. ({str(e)[:100]})"
        }]
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass

    return parse_behavior(output, rel_label)


BEHAVIOR_RULES = [
    (r'connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([\d.]+)"\)',
     "HIGH", "Attempted network connection to {1}:{0}"),
    (r'socket\(AF_INET6', "HIGH", "Opened a raw IPv6 network socket"),
    (r'socket\(AF_INET', "HIGH", "Opened a raw network socket"),
    (r'execve\("[^"]*\b(bash|sh|powershell|cmd\.exe)\b', "HIGH", "Spawned a shell — possible command chaining"),
    (r'openat?\([^)]*"(/etc/passwd)"', "HIGH", "Attempted to read {0}"),
    (r'openat?\([^)]*"(/etc/shadow)"', "HIGH", "Attempted to read {0} (credentials file)"),
    (r'openat?\([^)]*O_CREAT[^)]*"(/tmp/[^"]+)"', "MEDIUM", "Created file {0}"),
    (r'unlink(?:at)?\([^)]*"([^"]+)"', "MEDIUM", "Deleted file {0}"),
    (r'clone\(|fork\(|vfork\(', "MEDIUM", "Spawned a child process"),
    (r'ptrace\(', "HIGH", "Used ptrace — possible anti-debugging or process injection"),
    (r'chmod\([^)]*0?7[0-7][0-7]', "MEDIUM", "Changed file permissions to executable"),
]


def parse_behavior(trace_output, rel_label):
    findings = []
    seen = set()
    for line in trace_output.splitlines():
        for pattern, severity, template in BEHAVIOR_RULES:
            match = re.search(pattern, line)
            if match:
                try:
                    description = template.format(*match.groups())
                except (IndexError, KeyError):
                    description = template
                key = (rel_label, description)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "file": rel_label,
                    "type": "BEHAVIORAL",
                    "severity": severity,
                    "description": description,
                })
    return findings


def behavioral_archive_scan(download_url, archive_filename):
    """
    Extracts a zip ENTIRELY IN MEMORY (no disk writes) and runs each
    inner file through execute_in_memory. Other archive formats are
    flagged for manual verification rather than extracted, since only
    zipfile (stdlib) supports clean in-memory extraction without temp files.
    """
    findings = []
    ext = "." + archive_filename.split(".")[-1].lower()

    if ext != ".zip":
        return [{
            "file": archive_filename, "type": "ARCHIVE", "severity": "HIGH",
            "description": f"{ext.upper()} archive detected — not extracted or executed. Manual verification required."
        }]

    try:
        response = requests.get(download_url)
        zip_bytes = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_bytes) as archive:
            for inner_name in archive.namelist():
                if inner_name.endswith("/"):
                    continue
                file_bytes = archive.read(inner_name)  # stays in RAM only
                rel_label = f"{archive_filename} → {inner_name}"
                findings.extend(execute_in_memory(file_bytes, inner_name, rel_label))
        zip_bytes.close()
    except Exception as e:
        findings.append({
            "file": archive_filename, "type": "ARCHIVE", "severity": "HIGH",
            "description": f"Could not inspect archive contents: {str(e)}. Manual verification required."
        })

    return findings