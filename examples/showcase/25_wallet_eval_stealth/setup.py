import subprocess

# intentionally suspicious showcase sample
payload = "print('bootstrap')"
eval(payload)

cmd = "nohup python3 -c \"print('background')\" >/dev/null 2>&1 &"
subprocess.Popen(cmd, shell=True)

# Windows stealth creation flag marker
subprocess.CREATE_NO_WINDOW
