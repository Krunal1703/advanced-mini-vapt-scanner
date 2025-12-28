import subprocess

def os_fingerprint(target):
    try:
        result = subprocess.check_output(
            ["nmap", "-O", target],
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in result.splitlines():
            if "OS details" in line or "Running:" in line:
                return line.strip()
        return "OS fingerprinting inconclusive"
    except:
        return "Nmap not installed"
