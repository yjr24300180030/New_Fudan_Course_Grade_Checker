"""Direct session for accessing fdjwgl from the campus network.

When the host can already reach ``fdjwgl.fudan.edu.cn`` directly (on-campus
box, campus VPN client), there is no WebVPN gateway to authenticate to:
hitting the grade-sheet URL bounces straight into the IDP flow, and we
land back on fdjwgl with a session cookie.

``DirectSession`` mirrors :class:`src.webvpn.WebVPNSession`'s surface
(``login`` / ``get`` / ``post``) so :class:`src.grade_api.GradeClient`
can use either interchangeably.
"""

import html as html_mod
import re
import base64
from urllib.parse import urljoin

import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from src import config
from src.webvpn import _extract_lck


class DirectSession:
    """An authenticated fdjwgl session over a direct (non-VPN) connection."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.logged_in = False

    # ── public API (same shape as WebVPNSession) ─────────────────────────

    def login(self, student_id: str = None, password: str = None) -> bool:
        """Run the IDP flow for fdjwgl directly (no VPN).

        One combined handshake: hit the grade-sheet URL → fdjwgl redirects
        to IDP → IDP authenticates us → ticket back into fdjwgl.
        """
        student_id = student_id or config.STUDENT_ID
        password = password or config.PASSWORD
        if not student_id or not password:
            raise ValueError(
                "Student ID and password are required. "
                "Set StuId and UISPsw environment variables."
            )

        entity_id = config.GRADE_BASE

        print("[1/6] Triggering fdjwgl SSO redirect...")
        resp = self.session.get(
            config.GRADE_HOME_URL, allow_redirects=True, timeout=60,
        )
        lck = _extract_lck(resp)
        if not lck:
            raise RuntimeError(
                "Failed to extract lck from fdjwgl redirect "
                f"(final URL: {resp.url[:120]})"
            )
        print("    lck: OK")

        print("[2/6] Querying auth methods...")
        resp = self.session.post(
            f"{config.IDP_BASE}/idp/authn/queryAuthMethods",
            json={"lck": lck, "entityId": entity_id},
            headers={
                "Content-Type": "application/json",
                "Referer": f"{config.IDP_BASE}/ac/",
                "Origin": config.IDP_BASE,
            },
            timeout=60,
        )
        data = resp.json()
        request_type = data.get("requestType", "chain_type")
        auth_chain_code = ""
        for method in data.get("data", []):
            if method.get("moduleCode") == "userAndPwd":
                auth_chain_code = method.get("authChainCode", "")
                break
        if not auth_chain_code:
            raise RuntimeError("No authChainCode for fdjwgl")
        print("    authChainCode: OK")

        print("[3/6] Getting RSA public key...")
        resp = self.session.get(
            f"{config.IDP_BASE}/idp/authn/getJsPublicKey",
            headers={"Referer": f"{config.IDP_BASE}/ac/"},
            timeout=60,
        )
        pub_key_b64 = resp.json().get("data", "")
        if not pub_key_b64:
            raise RuntimeError("Failed to get public key")
        print("    Got RSA public key")

        print("[4/6] Encrypting password...")
        encrypted_password = _encrypt_password(password, pub_key_b64)

        print("[5/6] Executing authentication...")
        resp = self.session.post(
            f"{config.IDP_BASE}/idp/authn/authExecute",
            json={
                "authModuleCode": "userAndPwd",
                "authChainCode": auth_chain_code,
                "entityId": entity_id,
                "requestType": request_type,
                "lck": lck,
                "authPara": {
                    "loginName": student_id,
                    "password": encrypted_password,
                    "verifyCode": "",
                },
            },
            headers={
                "Content-Type": "application/json",
                "Referer": f"{config.IDP_BASE}/ac/",
                "Origin": config.IDP_BASE,
            },
            timeout=60,
        )
        data = resp.json()
        if str(data.get("code")) != "200":
            raise RuntimeError(f"fdjwgl auth failed (code={data.get('code')})")
        login_token = data.get("loginToken", "")
        if not login_token:
            raise RuntimeError("No loginToken in response")
        print("    loginToken: OK")

        print("[6/6] Following ticket into fdjwgl...")
        resp = self.session.post(
            f"{config.IDP_BASE}/idp/authCenter/authnEngine",
            data={"loginToken": login_token},
            headers={
                "Referer": f"{config.IDP_BASE}/ac/",
                "Origin": config.IDP_BASE,
            },
            timeout=60,
        )
        match = re.search(r'var locationValue = "([^"]+)"', resp.text)
        if not match:
            match = re.search(r'(https?://[^\s"\'<>]*ticket=[^\s"\'<>]*)', resp.text)
        if not match:
            raise RuntimeError("Failed to find ticket redirect in authnEngine")
        ticket_url = html_mod.unescape(match.group(1).replace("&amp;", "&"))
        resp = self.session.get(ticket_url, allow_redirects=True, timeout=60)
        # fdjwgl may emit a JS/meta client-side redirect; follow a couple.
        for _ in range(3):
            nxt = _extract_client_redirect(resp)
            if not nxt:
                break
            resp = self.session.get(nxt, allow_redirects=True, timeout=60)

        self.logged_in = True
        print("[*] fdjwgl direct login successful!")
        return True

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 30)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 30)
        return self.session.post(url, **kwargs)


def _encrypt_password(password: str, pub_key_b64: str) -> str:
    """RSA-encrypt the password (PKCS1_v1_5) and base64-encode it."""
    pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        + pub_key_b64
        + "\n-----END PUBLIC KEY-----"
    )
    rsa_key = RSA.import_key(pem)
    cipher = PKCS1_v1_5.new(rsa_key)
    return base64.b64encode(cipher.encrypt(password.encode("utf-8"))).decode("ascii")


_CLIENT_REDIRECT_PATTERNS = [
    re.compile(r'var\s+locationValue\s*=\s*["\']([^"\']+)["\']'),
    re.compile(r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']'),
    re.compile(r'(?:window\.)?location\.replace\(\s*["\']([^"\']+)["\']\s*\)'),
    re.compile(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\']+)["\']',
        re.IGNORECASE,
    ),
]


def _extract_client_redirect(resp: requests.Response) -> str | None:
    """fdjwgl sometimes hands back a JS or meta refresh redirect rather
    than a 302.  Return the next URL to visit, or None."""
    text = html_mod.unescape(resp.text or "")
    for pattern in _CLIENT_REDIRECT_PATTERNS:
        match = pattern.search(text)
        if match:
            return urljoin(resp.url, match.group(1).replace("&amp;", "&"))
    return None
