"""WebVPN URL encoding for Fudan University.

Fudan's WebVPN (webvpn.fudan.edu.cn) rewrites every upstream URL into a
proxy URL whose host segment is the AES-128-CFB ciphertext of the real
hostname, hex-encoded and prefixed with the IV.

    https://fdjwgl.fudan.edu.cn/student/for-std/grade/sheet/
        ->
    https://webvpn.fudan.edu.cn/https/<iv><ciphertext>/student/for-std/grade/sheet/

Only the URL-encoding helpers live here.  The authenticated session
(``WebVPNSession``) is defined below it.
"""

from binascii import hexlify, unhexlify
from urllib.parse import urlparse

from Crypto.Cipher import AES

from src import config


def encrypt_host(hostname: str) -> str:
    """Encrypt a hostname with AES-128-CFB; return hex ciphertext.

    The IV is fixed (config.WEBVPN_AES_IV) and prepended to the proxy URL
    in the clear, so we only return the ciphertext half here.
    """
    cipher = AES.new(
        config.WEBVPN_AES_KEY, AES.MODE_CFB, config.WEBVPN_AES_IV, segment_size=128
    )
    return hexlify(cipher.encrypt(hostname.encode("utf-8"))).decode("ascii")


def decrypt_host(ciphertext_hex: str) -> str:
    """Inverse of :func:`encrypt_host`."""
    cipher = AES.new(
        config.WEBVPN_AES_KEY, AES.MODE_CFB, config.WEBVPN_AES_IV, segment_size=128
    )
    return cipher.decrypt(unhexlify(ciphertext_hex)).decode("utf-8")


def get_vpn_url(url: str) -> str:
    """Convert a real URL into its WebVPN proxy URL.

    Example::

        https://fdjwgl.fudan.edu.cn/student/for-std/grade/sheet/info/123
        ->
        https://webvpn.fudan.edu.cn/https/<iv><host>/student/for-std/grade/sheet/info/123

    Non-standard ports are encoded as ``<scheme>-<port>``.
    """
    parsed = urlparse(url)
    protocol = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port

    # Re-attach path + query + fragment onto the proxy URL's tail.
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query
    if parsed.fragment:
        path += "#" + parsed.fragment
    path = path.lstrip("/")

    iv_hex = hexlify(config.WEBVPN_AES_IV).decode("ascii")
    encrypted = encrypt_host(hostname)

    # Encode non-default ports so the proxy can dial them.
    port_suffix = ""
    if port and not (
        (protocol == "http" and port == 80)
        or (protocol == "https" and port == 443)
    ):
        port_suffix = f"-{port}"

    vpn_url = f"{config.WEBVPN_BASE}/{protocol}{port_suffix}/{iv_hex}{encrypted}"
    if path:
        vpn_url += f"/{path}"
    return vpn_url


def get_ordinary_url(vpn_url: str) -> str:
    """Convert a WebVPN proxy URL back to the real URL it points at."""
    parsed = urlparse(vpn_url)
    parts = parsed.path.strip("/").split("/", 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid WebVPN URL: {vpn_url}")

    protocol_part, encoded_host = parts[0], parts[1]
    rest = parts[2] if len(parts) > 2 else ""

    # protocol_part looks like "https" or "https-8080"
    if "-" in protocol_part:
        protocol, port_str = protocol_part.rsplit("-", 1)
        port = f":{port_str}"
    else:
        protocol, port = protocol_part, ""

    # Strip the 32-char IV hex prefix, then decrypt the host.
    hostname = decrypt_host(encoded_host[32:])

    original = f"{protocol}://{hostname}{port}"
    if rest:
        original += f"/{rest}"
    if parsed.query:
        original += f"?{parsed.query}"
    return original
