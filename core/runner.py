import subprocess

def run(cmd):
    out = subprocess.getoutput(cmd)
    if "not found" in out.lower():
        return ""
    return out.strip()
