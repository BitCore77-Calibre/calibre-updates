#!/usr/bin/env python3
"""CALIBRE signed files: one format, one key and one check for every file CALIBRE apps
download and trust (the release list, the wallet settings file, the MBM DEX partner files).
Format and rules: docs/SIGNED_FILES.md. Test networks only; CLX has no value.

    signed_files.py keygen  --key-dir DIR                     make the admin signing key (offline; asks a passphrase)
    signed_files.py pubkey  --key-dir DIR                     print the public key entry the apps build in
    signed_files.py sign    --key-dir DIR --kind K --id ID [--previous FILE | --first] [--history DIR] [--earlier-keys KEYS.json]
                            [--days N] PAYLOAD.json OUT.json  sign a payload (serial = previous + 1)
    signed_files.py rollback --key-dir DIR --good OLD.json --current CUR.json OUT.json
                                                              re-sign OLD's payload with serial CUR + 1
    signed_files.py verify  --keys KEYS.json --kind K --id ID [--state STATE.json] FILE.json
                                                              the check every app runs; prints the payload
    signed_files.py show    FILE.json                         print the body without checking (for people)
    signed_files.py vectors OUT_DIR                           write the conformance vectors (docs/SIGNED_FILES.md)

The private key never leaves the key folder and is stored encrypted (scrypt + AES-256-GCM);
the passphrase is typed into a hidden prompt (or CALIBRE_SIGNING_PASSPHRASE for tests).
Needs Python 3.11+ and cryptography 48+ (ML-DSA through OpenSSL 3.5+).
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT = "calibre-signed-file/1"
KEY_FORMAT = "calibre-signing-key/1"
CONTEXT = FORMAT.encode()                     # ML-DSA-65 context string (FIPS 204)
ED_PREFIX = CONTEXT + b"\x00"                 # Ed25519 signs ED_PREFIX + body bytes
MAX_BODY = 1 << 20                            # 1 MiB
CLOCK_SKEW = timedelta(minutes=10)
ML_DSA_SIG_LEN, ED_SIG_LEN = 3309, 64
ML_DSA_PUB_LEN, ED_PUB_LEN = 1952, 32

# kind → (how long a file may live at most, default lifetime when signing, id rule)
KINDS = {
    # The release list may live long: its freshness comes from the timestamp file, re-signed
    # automatically every 12 hours with the timestamp key (docs/SIGNED_FILES.md section 8).
    "release-list": (timedelta(days=120), 90, re.compile(r"^releases$")),
    "timestamp": (timedelta(days=7), 3, re.compile(r"^releases-timestamp$")),
    "wallet-settings": (timedelta(days=30), 14, re.compile(r"^wallet-settings$")),
    "partner": (timedelta(days=90), 30, re.compile(r"^partner:[a-z0-9][a-z0-9-]{1,39}$")),
}
TIME_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


class Refused(Exception):
    """A file that must not be used. `code` is stable (apps and tests match on it)."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str, length: int, what: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", text):
        raise Refused("bad-encoding", f"{what} is not standard base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:  # binascii.Error: bad padding
        raise Refused("bad-encoding", f"{what} is not standard base64") from None
    if len(raw) != length or b64(raw) != text:
        raise Refused("bad-encoding", f"{what} must be {length} bytes in canonical base64")
    return raw


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: object, what: str) -> datetime:
    if not isinstance(text, str) or not TIME_RE.match(text):
        raise Refused("bad-body", f"{what} must be UTC like 2026-11-04T10:00:00Z")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def key_id(ml_pub: bytes, ed_pub: bytes) -> str:
    return hashlib.sha256(b"calibre-signing-key-id/1\x00" + ml_pub + ed_pub).hexdigest()[:16]


# ------------------------------------------------------------------ keys

def _scrypt(salt: bytes) -> Scrypt:
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)


def write_key(key_dir: Path, ml_seed: bytes, ed_seed: bytes, passphrase: str, role: str = "files") -> dict:
    ml_pub = mldsa.MLDSA65PrivateKey.from_seed_bytes(ml_seed).public_key().public_bytes_raw()
    ed_pub = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed).public_key().public_bytes_raw()
    kid = key_id(ml_pub, ed_pub)
    salt, nonce = os.urandom(16), os.urandom(12)
    box = AESGCM(_scrypt(salt).derive(passphrase.encode())).encrypt(nonce, ml_seed + ed_seed, kid.encode())
    key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    private = {"format": KEY_FORMAT, "key_id": kid, "kdf": {"name": "scrypt", "n": 2**17, "r": 8, "p": 1, "salt": b64(salt)},
               "cipher": "aes-256-gcm", "nonce": b64(nonce), "secret": b64(box)}
    public = {"key_id": kid, "ml-dsa-65": b64(ml_pub), "ed25519": b64(ed_pub), "roles": [role]}
    path = key_dir / "signing-key.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(private, f, indent=1)
    (key_dir / "signing-public.json").write_text(json.dumps(public, indent=1) + "\n")
    return public


def read_key(key_dir: Path, passphrase: str):
    data = json.loads((key_dir / "signing-key.json").read_text())
    if data.get("format") != KEY_FORMAT:
        raise SystemExit("not a CALIBRE signing key")
    kdf = data["kdf"]
    try:
        raw = AESGCM(_scrypt(base64.b64decode(kdf["salt"])).derive(passphrase.encode())).decrypt(
            base64.b64decode(data["nonce"]), base64.b64decode(data["secret"]), data["key_id"].encode())
    except InvalidTag:
        raise SystemExit("wrong passphrase") from None
    ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(raw[:32])
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(raw[32:64])
    if key_id(ml.public_key().public_bytes_raw(), ed.public_key().public_bytes_raw()) != data["key_id"]:
        raise SystemExit("key file is damaged")
    return data["key_id"], ml, ed


def passphrase(confirm: bool = False) -> str:
    env = os.environ.get("CALIBRE_SIGNING_PASSPHRASE")
    if env:
        return env
    first = getpass.getpass("Signing key passphrase: ")
    if confirm:
        if len(first) < 12:
            raise SystemExit("use at least 12 characters")
        if getpass.getpass("Same passphrase again: ") != first:
            raise SystemExit("the two passphrases differ")
    return first


# ------------------------------------------------------------------ signing

def make_body(kind: str, file_id: str, serial: int, issued: datetime, expires: datetime,
              previous: str | None, payload: dict) -> bytes:
    body = {"kind": kind, "id": file_id, "serial": serial, "issued": iso(issued), "expires": iso(expires),
            "previous": previous, "payload": payload}
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode()


def seal(body: bytes, kid: str, ml, ed) -> dict:
    return {"format": FORMAT, "key_id": kid, "body": body.decode(),
            "sig": {"ml-dsa-65": b64(ml.sign(body, CONTEXT)), "ed25519": b64(ed.sign(ED_PREFIX + body))}}


def channel_downgrades(payload: dict, earlier_payloads: list[dict]) -> list[str]:
    """A channel never goes below the highest version it ever had in any earlier release list
    (its high-water mark), even if the channel or product was left out in between. So every
    pre-release an install got from a list is at most the one listed now and gets replaced.
    `rollback` is the only exception (it undoes a bad list; the next normal list is held to
    the high-water mark again)."""
    high: dict[tuple[str, str], str] = {}
    for old in earlier_payloads:
        for prod, entry in (old.get("products") or {}).items():
            for name, rel in ((entry or {}).get("channels") or {}).items():
                try:
                    v = rel["version"]
                    if (prod, name) not in high or version_key(v) > version_key(high[(prod, name)]):
                        high[(prod, name)] = v
                except (ValueError, TypeError, KeyError):
                    pass
    out = []
    for prod, entry in payload.get("products", {}).items():
        for name, rel in entry["channels"].items():
            h = high.get((prod, name))
            if h is not None and version_key(rel["version"]) < version_key(h):
                out.append(f"products.{prod}.channels.{name}: {rel['version']} is below {h}, already published on this channel")
    return out


def history_chain(files: list[dict], previous_file: dict, kind: str, file_id: str, key,
                  earlier_keys: list[dict] | None = None) -> list[dict]:
    """The earlier payloads, after checking that history + previous form one unbroken chain:
    serials 1..N, each `previous` the SHA-256 of the body before, every file signed by this key
    (or, after a key rotation, by a key in `earlier_keys`: public entries, docs/runbooks/RB-01)
    for this kind and id, and previous is serial N. A missing, extra or forged file stops signing."""
    kid, ml, ed = key
    pubs = {kid: (ml.public_key(), ed.public_key())}
    for k in earlier_keys or []:
        try:
            mp, ep = unb64(k["ml-dsa-65"], ML_DSA_PUB_LEN, "ML-DSA-65 key"), unb64(k["ed25519"], ED_PUB_LEN, "Ed25519 key")
            if key_id(mp, ep) != k["key_id"]:
                raise ValueError("entry does not match its key_id")
        except (KeyError, TypeError, ValueError, Refused) as e:
            raise SystemExit(f"earlier keys: a bad public key entry ({e})") from None
        pubs[k["key_id"]] = (mldsa.MLDSA65PublicKey.from_public_bytes(mp), ed25519.Ed25519PublicKey.from_public_bytes(ep))
    by_serial: dict[int, dict] = {}
    for f in [*files, previous_file]:
        try:
            body = f["body"].encode()
            if f.get("format") != FORMAT or f.get("key_id") not in pubs:
                raise ValueError("another format, or a key that is neither this one nor an earlier key")
            ml_pub, ed_pub = pubs[f["key_id"]]
            ml_pub.verify(unb64(f["sig"]["ml-dsa-65"], ML_DSA_SIG_LEN, "ML-DSA-65 signature"), body, CONTEXT)
            ed_pub.verify(unb64(f["sig"]["ed25519"], ED_SIG_LEN, "Ed25519 signature"), ED_PREFIX + body)
            b = json.loads(body)
        except (KeyError, TypeError, ValueError, InvalidSignature, Refused, AttributeError) as e:
            raise SystemExit(f"history: a file is not a good signed file of this key ({e})") from None
        if b.get("kind") != kind or b.get("id") != file_id:
            raise SystemExit(f"history: serial {b.get('serial')} is for another kind or id")
        n = b.get("serial")
        if n in by_serial and by_serial[n]["body"] != f["body"]:
            raise SystemExit(f"history: two different files with serial {n}")
        by_serial[n] = f
    last = json.loads(previous_file["body"])["serial"]
    if sorted(by_serial) != list(range(1, last + 1)):
        missing = sorted(set(range(1, last + 1)) - set(by_serial))
        raise SystemExit(f"history: not complete up to the previous file's serial {last}"
                         + (f" (missing {missing[:10]})" if missing else " (files after it)"))
    before = None
    for n in range(1, last + 1):
        b = json.loads(by_serial[n]["body"])
        if b["previous"] != before:
            raise SystemExit(f"history: serial {n} does not link to serial {n - 1}")
        before = hashlib.sha256(by_serial[n]["body"].encode()).hexdigest()
    return [json.loads(by_serial[n]["body"])["payload"] for n in range(1, last + 1)]


def sign_file(key, kind: str, file_id: str, payload: dict, previous_file: dict | None,
              now: datetime | None = None, days: int | None = None, rollback: bool = False,
              history: list[dict] | None = None, earlier_keys: list[dict] | None = None) -> dict:
    """`history`: every earlier signed file of this id (release lists need it, see channel_downgrades)."""
    if kind not in KINDS:
        raise SystemExit(f"unknown kind {kind}")
    lifetime, default_days, id_rule = KINDS[kind]
    if kind == "timestamp" and (problems := timestamp_problems(payload)):
        raise SystemExit("not signed, the timestamp payload has problems:\n  " + "\n  ".join(problems))
    if kind == "release-list" and (problems := release_list_problems(payload)):
        raise SystemExit("not signed, the release list has problems:\n  " + "\n  ".join(problems))
    if not id_rule.match(file_id):
        raise SystemExit(f"id {file_id!r} is not allowed for kind {kind}")
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    expires = now + timedelta(days=days or default_days)
    if expires - now > lifetime:
        raise SystemExit(f"a {kind} file may live at most {lifetime.days} days")
    serial, prev = 1, None
    if previous_file is not None:
        pb = json.loads(previous_file["body"])
        if pb["kind"] != kind or pb["id"] != file_id:
            raise SystemExit("the previous file is for another kind or id")
        serial, prev = pb["serial"] + 1, hashlib.sha256(previous_file["body"].encode()).hexdigest()
        if kind == "release-list" and not rollback and history is None:
            raise SystemExit("a release list needs --history (every earlier list) to check channel versions")
        if kind == "release-list" and not rollback and (
                down := channel_downgrades(payload, history_chain(history, previous_file, kind, file_id, key, earlier_keys))):
            raise SystemExit("not signed, a channel would go down (use rollback for that):\n  " + "\n  ".join(down))
    if kind == "timestamp":
        # serial = minutes since 1970, so a lost earlier timestamp can never reset it to 1
        # (apps would refuse a lower serial); it still links to the previous one when given
        clock = int(now.timestamp() // 60)
        if previous_file is not None and clock <= serial - 1:
            raise SystemExit("the previous timestamp is from the same minute or the future: wait a minute")
        serial = clock
    kid, ml, ed = key
    return seal(make_body(kind, file_id, serial, now, expires, prev, payload), kid, ml, ed)


# ------------------------------------------------------------------ the check every app runs

def verify(file_bytes: bytes, keys: list[dict], kind: str, file_id: str, now: datetime,
           last_good: dict | None = None) -> dict:
    """Returns {"body": text, "serial", "sha256", "payload", "expires"} or raises Refused.
    `last_good` is what the app stored after its last accepted file: {"serial", "sha256", "key_id"}.
    A stored serial accepted under a key that is no longer in `keys` is forgotten: after a stolen
    key is dropped from the apps, a very high serial its thief signed cannot block the new key's
    files (docs/runbooks/RB-01), and that key's own files are refused anyway."""
    if len(file_bytes) > 4 * MAX_BODY:
        raise Refused("too-large", "file is larger than 4 MiB")
    try:
        outer = json.loads(file_bytes)
    except (ValueError, UnicodeDecodeError):
        raise Refused("bad-json", "not JSON") from None
    if not isinstance(outer, dict) or outer.get("format") != FORMAT:
        raise Refused("bad-format", f"format must be {FORMAT}")
    if set(outer) != {"format", "key_id", "body", "sig"} or not isinstance(outer["sig"], dict) \
            or set(outer["sig"]) != {"ml-dsa-65", "ed25519"} or not isinstance(outer["body"], str):
        raise Refused("bad-format", "fields must be exactly format, key_id, body, sig{ml-dsa-65, ed25519}")
    key = next((k for k in keys if k.get("key_id") == outer["key_id"]), None)
    if key is None:
        raise Refused("unknown-key", f"key {outer['key_id']!r} is not built into this app")
    # roles come from the app's built-in key list and are required on every entry: the timestamp
    # key signs only timestamps, the owner's key ("files") never signs one; no roles, no use
    roles = key.get("roles")
    if not isinstance(roles, list) or ("timestamp" if kind == "timestamp" else "files") not in roles:
        raise Refused("wrong-role", f"key {outer['key_id']} may not sign a {kind} file")
    body = outer["body"].encode()
    if len(body) > MAX_BODY:
        raise Refused("too-large", "body is larger than 1 MiB")
    ml_pub = unb64(key["ml-dsa-65"], ML_DSA_PUB_LEN, "built-in ML-DSA-65 key")
    ed_pub = unb64(key["ed25519"], ED_PUB_LEN, "built-in Ed25519 key")
    if key_id(ml_pub, ed_pub) != key["key_id"]:
        raise Refused("unknown-key", "built-in key entry does not match its key_id")
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(ml_pub).verify(
            unb64(outer["sig"]["ml-dsa-65"], ML_DSA_SIG_LEN, "ML-DSA-65 signature"), body, CONTEXT)
        ed25519.Ed25519PublicKey.from_public_bytes(ed_pub).verify(
            unb64(outer["sig"]["ed25519"], ED_SIG_LEN, "Ed25519 signature"), ED_PREFIX + body)
    except InvalidSignature:
        raise Refused("bad-signature", "a signature does not match") from None
    try:
        b = json.loads(body)
    except ValueError:
        raise Refused("bad-body", "body is not JSON") from None
    if not isinstance(b, dict) or set(b) != {"kind", "id", "serial", "issued", "expires", "previous", "payload"}:
        raise Refused("bad-body", "body fields must be exactly kind, id, serial, issued, expires, previous, payload")
    if b["kind"] != kind or kind not in KINDS:
        raise Refused("wrong-kind", f"expected {kind}, file is {b['kind']!r}")
    if b["id"] != file_id or not KINDS[kind][2].match(file_id):
        raise Refused("wrong-id", f"expected {file_id}, file is {b['id']!r}")
    if type(b["serial"]) is not int or not 1 <= b["serial"] < 2**53:
        raise Refused("bad-body", "serial must be a whole number from 1")
    if b["previous"] is not None and not (isinstance(b["previous"], str) and re.fullmatch(r"[0-9a-f]{64}", b["previous"])):
        raise Refused("bad-body", "previous must be null or a SHA-256 in hex")
    if not isinstance(b["payload"], dict):
        raise Refused("bad-body", "payload must be an object")
    issued, expires = parse_time(b["issued"], "issued"), parse_time(b["expires"], "expires")
    if issued > now + CLOCK_SKEW:
        raise Refused("not-yet-valid", f"issued {b['issued']} is in the future")
    if now >= expires:
        raise Refused("expired", f"expired {b['expires']}")
    if expires - issued > KINDS[kind][0] or expires <= issued:
        raise Refused("bad-lifetime", f"a {kind} file may live at most {KINDS[kind][0].days} days")
    if kind == "timestamp" and b["serial"] != int(issued.timestamp() // 60):
        # the serial is the minute it was issued, and issued may be at most 10 minutes ahead,
        # so even a stolen timestamp key cannot sign a huge serial that blocks later timestamps
        raise Refused("bad-body", "a timestamp's serial must be the minute of its issued time")
    digest = hashlib.sha256(body).hexdigest()
    if last_good is not None and last_good.get("key_id") not in (None, *(k.get("key_id") for k in keys)):
        last_good = None
    if last_good is not None:
        if b["serial"] < last_good["serial"] or (b["serial"] == last_good["serial"] and digest != last_good["sha256"]):
            raise Refused("old-serial", f"serial {b['serial']} is older than the {last_good['serial']} already accepted")
    return {"body": outer["body"], "serial": b["serial"], "sha256": digest, "payload": b["payload"], "expires": b["expires"],
            "key_id": outer["key_id"]}


# ------------------------------------------------------------------ freshness (timestamp)

def timestamp_problems(payload: object) -> list[str]:
    """Empty when a timestamp payload is exactly {releases_serial, releases_sha256}."""
    if not isinstance(payload, dict) or set(payload) != {"releases_serial", "releases_sha256"}:
        return ["payload must be exactly {releases_serial, releases_sha256}"]
    p = []
    if type(payload["releases_serial"]) is not int or not 1 <= payload["releases_serial"] < 2**53:
        p.append("releases_serial: a whole number from 1")
    if not (isinstance(payload["releases_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", payload["releases_sha256"])):
        p.append("releases_sha256: 64 lowercase hex")
    return p


def check_fresh(releases: dict, timestamp: dict) -> None:
    """Both are verify() results. The release list counts only when a valid, unexpired timestamp
    names exactly its body (sha256 and serial); otherwise the app keeps its last good pair, and
    when that timestamp has expired too it shows no update offers (a frozen or stale list)."""
    t = timestamp["payload"]
    if timestamp_problems(t):
        raise Refused("bad-payload", "timestamp payload: " + "; ".join(timestamp_problems(t)))
    if (t["releases_sha256"], t["releases_serial"]) != (releases["sha256"], releases["serial"]):
        raise Refused("not-fresh", f"the timestamp names release list serial {t['releases_serial']}, "
                                   f"not serial {releases['serial']}")


# ------------------------------------------------------------------ staged rollout (release list)

def rollout_bucket(install_id: str, product: str, version: str) -> int:
    """0..9999; an install gets a release once the rollout percent * 100 is above its bucket."""
    h = hashlib.sha256(f"calibre-rollout/1\n{install_id}\n{product}\n{version}".encode()).digest()
    return int.from_bytes(h[:4], "big") % 10000


def rollout_percent(rollout: dict, now: datetime) -> int:
    if rollout.get("paused"):
        return 0
    start = parse_time(rollout["start"], "rollout.start")
    pct = 0
    for hours, percent in rollout["stages"]:
        if now >= start + timedelta(hours=hours):
            pct = max(pct, percent)
    return pct


def offered(release: dict, install_id: str, product: str, now: datetime) -> bool:
    """Whether this install sees "Update available" for this release now."""
    if release.get("required"):
        return True
    return rollout_bucket(install_id, product, release["version"]) < rollout_percent(release["rollout"], now) * 100


# ------------------------------------------------------------------ release channels (release list)

PRODUCTS = ("calibre-wallet", "calibre-control-room", "calibre-node", "calibre-validator", "mbm-dex-web",
            "mbm-dex-whitelabel", "calibre-terminal", "calibre-website")
CHANNELS = ("stable", "beta", "edge")
FOLLOWS = {"stable": ("stable",), "beta": ("stable", "beta"), "edge": ("stable", "beta", "edge")}
# who may choose which channel (docs/SIGNED_FILES.md section 5); edge is the owner's lab only
ALLOWED = {"calibre-wallet": ("stable", "beta", "edge"), "calibre-control-room": ("stable", "beta", "edge"),
           "calibre-terminal": ("stable", "beta", "edge"), "calibre-node": ("stable", "beta", "edge"),
           "calibre-validator": ("stable", "edge"), "mbm-dex-whitelabel": ("stable", "beta"),
           "mbm-dex-web": ("stable",), "calibre-website": ("stable",)}
# ASCII digits only and fullmatch (no trailing newline): every port must read the same strings
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
                    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?", re.ASCII)
MAX_STAGE_HOURS = 24 * 90                     # a rollout lasts at most 90 days
LATEST_START = datetime(2100, 1, 1, tzinfo=timezone.utc)
FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", re.ASCII)
PLATFORM = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}", re.ASCII)
RELEASE_FIELDS = {"version", "required", "reason", "notes_url", "files", "rollout"}
FILE_FIELDS = {"platform", "name", "url", "sha256", "size"}


def version_key(v: str) -> tuple:
    """Semantic Versioning 2.0 order: 0.3.0-beta.1 < 0.3.0-rc.1 < 0.3.0 < 0.3.1."""
    m = SEMVER.fullmatch(v)
    if not m:
        raise ValueError(f"not a version: {v!r}")
    pre = m.group(4)
    parts = () if pre is None else tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre is None, parts)


def release_list_problems(payload: object) -> list[str]:
    """Empty when the release-list payload follows section 5. Apps treat a non-empty answer like a
    refused file (`bad-payload`: keep the last good list); `sign` refuses to sign it."""
    p: list[str] = []
    if not isinstance(payload, dict) or set(payload) != {"products"} or not isinstance(payload["products"], dict):
        return ["payload must be exactly {products: {...}}"]
    for prod, entry in payload["products"].items():
        w = f"products.{prod}"
        if prod not in PRODUCTS:
            p.append(f"{w}: unknown product"); continue
        if not isinstance(entry, dict) or set(entry) != {"min_version", "channels"}:
            p.append(f"{w}: fields must be exactly min_version, channels"); continue
        if entry["min_version"] is not None and not (isinstance(entry["min_version"], str) and SEMVER.fullmatch(entry["min_version"])):
            p.append(f"{w}.min_version: null or a version")
        ch = entry["channels"]
        if not isinstance(ch, dict) or not ch:
            p.append(f"{w}.channels: at least one channel"); continue
        for name, rel in ch.items():
            c = f"{w}.channels.{name}"
            if name not in ALLOWED[prod]:
                p.append(f"{c}: {prod} has no {name} channel (allowed: {', '.join(ALLOWED[prod])})"); continue
            if not isinstance(rel, dict) or set(rel) != RELEASE_FIELDS:
                p.append(f"{c}: fields must be exactly {', '.join(sorted(RELEASE_FIELDS))}"); continue
            if not (isinstance(rel["version"], str) and SEMVER.fullmatch(rel["version"])):
                p.append(f"{c}.version: not a version"); continue
            if name == "stable" and "-" in rel["version"]:
                p.append(f"{c}.version: stable takes no pre-release ({rel['version']})")
            if type(rel["required"]) is not bool:
                p.append(f"{c}.required: true or false")
            elif rel["required"]:
                if not (isinstance(rel["reason"], str) and rel["reason"].strip()):
                    p.append(f"{c}.reason: a required update must say why")
                if name != "stable" and not (isinstance(ch.get("stable"), dict) and ch["stable"].get("required") is True):
                    p.append(f"{c}.required: a security update ships on stable too (stable must be required in the same list)")
            if rel["reason"] is not None and not isinstance(rel["reason"], str):
                p.append(f"{c}.reason: null or text")
            if not (isinstance(rel["notes_url"], str) and rel["notes_url"].startswith("https://")):
                p.append(f"{c}.notes_url: an https:// link")
            files = rel["files"]
            if not isinstance(files, list):
                p.append(f"{c}.files: a list")
            else:
                for i, f in enumerate(files):
                    if not isinstance(f, dict) or set(f) != FILE_FIELDS:
                        p.append(f"{c}.files[{i}]: fields must be exactly {', '.join(sorted(FILE_FIELDS))}"); continue
                    if not (isinstance(f["platform"], str) and PLATFORM.fullmatch(f["platform"])):
                        p.append(f"{c}.files[{i}].platform: like linux-x86_64")
                    elif sum(isinstance(g, dict) and g.get("platform") == f["platform"] for g in files) > 1:
                        p.append(f"{c}.files[{i}].platform: {f['platform']} appears twice")
                    if not (isinstance(f["name"], str) and FILE_NAME.fullmatch(f["name"]) and ".." not in f["name"]):
                        p.append(f"{c}.files[{i}].name: a plain file name (letters, digits, . _ + -; no folders)")
                    if not (isinstance(f["url"], str) and f["url"].startswith("https://")):
                        p.append(f"{c}.files[{i}].url: an https:// link")
                    if not (isinstance(f["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", f["sha256"])):
                        p.append(f"{c}.files[{i}].sha256: 64 lowercase hex")
                    if type(f["size"]) is not int or f["size"] <= 0:
                        p.append(f"{c}.files[{i}].size: bytes, above 0")
            r = rel["rollout"]
            if not isinstance(r, dict) or set(r) != {"start", "stages", "paused"} or type(r.get("paused")) is not bool:
                p.append(f"{c}.rollout: fields must be exactly start, stages, paused"); continue
            try:
                if parse_time(r["start"], "rollout.start") >= LATEST_START:
                    p.append(f"{c}.rollout.start: before 2100")
            except Refused:
                p.append(f"{c}.rollout.start: UTC time like 2026-11-04T10:00:00Z")
            st = r["stages"]
            ok = isinstance(st, list) and st and all(isinstance(s, list) and len(s) == 2 and all(type(x) is int for x in s) for s in st)
            if not ok or any(not (0 <= h <= MAX_STAGE_HOURS) or not (1 <= pc <= 100) for h, pc in st) \
                    or any(a[0] >= b[0] or a[1] >= b[1] for a, b in zip(st, st[1:])) or st[-1][1] != 100:
                p.append(f"{c}.rollout.stages: [[hours, percent], …] both rising, hours 0–{MAX_STAGE_HOURS}, percent 1–100, ending at 100")
        # the security floor must be reachable from stable, so nobody has to leave stable to be safe
        mv, stable = entry["min_version"], ch.get("stable")
        if isinstance(mv, str) and SEMVER.fullmatch(mv):
            if "-" in mv:
                p.append(f"{w}.min_version: no pre-release ({mv})")
            elif not (isinstance(stable, dict) and isinstance(stable.get("version"), str) and SEMVER.fullmatch(stable["version"])
                      and version_key(stable["version"]) >= version_key(mv)):
                p.append(f"{w}.min_version: stable must carry {mv} or newer")
        # a required stable fix must reach installs on a pre-release too
        if isinstance(stable, dict) and stable.get("required") is True:
            for name in ("beta", "edge"):
                pre = ch.get(name)
                if not isinstance(pre, dict):
                    continue
                if pre.get("required") is not True:
                    p.append(f"{w}.channels.{name}.required: stable is a required security update, so {name} must carry the fix as required too")
                try:
                    if version_key(pre["version"]) <= version_key(stable["version"]):
                        p.append(f"{w}.channels.{name}.version: must be above the required stable {stable['version']} "
                                 f"(a pre-release of a later version that has the fix)")
                except (ValueError, TypeError, KeyError):
                    pass
    return p


def choose_update(entry: dict, channel: str, current: str, install_id: str, product: str, now: datetime) -> dict | None:
    """What one install is offered from its product's entry in a checked release list.
    A channel follows the steadier ones too: beta also gets stable, edge gets beta and stable.
    Returns None (up to date) or {"version", "channel", "required", "reason", "notes_url", "files"}."""
    if channel not in FOLLOWS:
        channel = "stable"                                    # unknown setting: the safe choice
    cur = version_key(current)
    below_min = entry["min_version"] is not None and cur < version_key(entry["min_version"])
    newer = [(name, rel) for name in FOLLOWS[channel] if (rel := entry["channels"].get(name))
             and version_key(rel["version"]) > cur]
    if below_min:      # every older version is treated as required: rollout stages do not apply
        pool = [(n, r) for n, r in newer if version_key(r["version"]) >= version_key(entry["min_version"])]
    else:
        pool = [(n, r) for n, r in newer if offered(r, install_id, product, now)]
    if not pool:
        return None
    name, best = max(pool, key=lambda nr: version_key(nr[1]["version"]))
    req = [r for _, r in pool if r["required"]]
    required = below_min or bool(req)
    reason = (req[0]["reason"] if req else None) or (f"versions below {entry['min_version']} are no longer safe" if below_min else None)
    return {"version": best["version"], "channel": name, "required": required, "reason": reason,
            "notes_url": best["notes_url"], "files": best["files"]}


# ------------------------------------------------------------------ conformance vectors

TEST_ML_SEED = bytes(range(32))           # PUBLIC test key: never use for real files
TEST_ED_SEED = bytes(range(32, 64))


def test_key():
    ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(TEST_ML_SEED)
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(TEST_ED_SEED)
    pub = {"key_id": key_id(ml.public_key().public_bytes_raw(), ed.public_key().public_bytes_raw()),
           "ml-dsa-65": b64(ml.public_key().public_bytes_raw()), "ed25519": b64(ed.public_key().public_bytes_raw()),
           "roles": ["files"]}
    return (pub["key_id"], ml, ed), pub


def test_timestamp_key():
    """A second PUBLIC test key with the timestamp role (seeds 64..95 and 96..127)."""
    ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(range(64, 96)))
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
    pub = {"key_id": key_id(ml.public_key().public_bytes_raw(), ed.public_key().public_bytes_raw()),
           "ml-dsa-65": b64(ml.public_key().public_bytes_raw()), "ed25519": b64(ed.public_key().public_bytes_raw()),
           "roles": ["timestamp"]}
    return (pub["key_id"], ml, ed), pub


def vectors(out: Path) -> list[dict]:
    """Files every implementation must accept or refuse with the same code (docs/SIGNED_FILES.md)."""
    key, pub = test_key()
    kid, ml, ed = key
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    now = t0 + timedelta(hours=1)
    payload = {"products": {"calibre-wallet": {"min_version": None, "channels": {"stable": {
               "version": "0.3.0", "required": False, "reason": None,
               "notes_url": "https://github.com/BitCore77-Calibre/calibre-wallet/releases/tag/v0.3.0",
               "files": [], "rollout": {"start": "2026-11-04T10:00:00Z", "stages": [[0, 10], [24, 50], [48, 100]], "paused": False}}}}}}
    good = sign_file(key, "release-list", "releases", payload, None, now=t0)
    second = sign_file(key, "release-list", "releases", payload, good, now=t0, history=[])
    tkey, tpub = test_timestamp_key()
    stamp = {"releases_serial": 1, "releases_sha256": hashlib.sha256(good["body"].encode()).hexdigest()}
    ts_good = sign_file(tkey, "timestamp", "releases-timestamp", stamp, None, now=t0)

    def tamper(f, fn):
        g = json.loads(json.dumps(f)); fn(g); return g

    def body_edit(f, fn):
        b = json.loads(f["body"]); fn(b)
        return seal(json.dumps(b, separators=(",", ":")).encode(), kid, ml, ed)

    cases = [
        ("good", good, "release-list", "releases", None, "ok"),
        ("good-second-after-first", second, "release-list", "releases", {"serial": 1, "sha256": hashlib.sha256(good["body"].encode()).hexdigest()}, "ok"),
        ("same-file-again", good, "release-list", "releases", {"serial": 1, "sha256": hashlib.sha256(good["body"].encode()).hexdigest()}, "ok"),
        ("older-serial", good, "release-list", "releases", {"serial": 2, "sha256": hashlib.sha256(second["body"].encode()).hexdigest()}, "old-serial"),
        ("same-serial-other-body", second, "release-list", "releases", {"serial": 2, "sha256": "0" * 64}, "old-serial"),
        ("body-changed", tamper(good, lambda g: g.update(body=g["body"].replace('"0.3.0"', '"9.9.9"'))), "release-list", "releases", None, "bad-signature"),
        ("ml-dsa-signature-of-other-file", tamper(good, lambda g: g["sig"].update({"ml-dsa-65": second["sig"]["ml-dsa-65"]})), "release-list", "releases", None, "bad-signature"),
        ("ed25519-signature-of-other-file", tamper(good, lambda g: g["sig"].update({"ed25519": second["sig"]["ed25519"]})), "release-list", "releases", None, "bad-signature"),
        ("ed25519-missing", tamper(good, lambda g: g["sig"].pop("ed25519")), "release-list", "releases", None, "bad-format"),
        ("unknown-key", tamper(good, lambda g: g.update(key_id="0123456789abcdef")), "release-list", "releases", None, "unknown-key"),
        ("wrong-kind", good, "wallet-settings", "wallet-settings", None, "wrong-kind"),
        ("wrong-id", body_edit(good, lambda b: b.update(id="partner:acme")), "release-list", "releases", None, "wrong-id"),
        ("expired", body_edit(good, lambda b: b.update(expires="2026-11-04T10:30:00Z")), "release-list", "releases", None, "expired"),
        ("issued-in-future", body_edit(good, lambda b: b.update(issued="2026-11-04T12:00:00Z")), "release-list", "releases", None, "not-yet-valid"),
        ("lives-too-long", body_edit(good, lambda b: b.update(expires="2027-12-04T10:00:00Z")), "release-list", "releases", None, "bad-lifetime"),
        ("extra-body-field", body_edit(good, lambda b: b.update(extra=1)), "release-list", "releases", None, "bad-body"),
        ("serial-not-integer", body_edit(good, lambda b: b.update(serial=1.5)), "release-list", "releases", None, "bad-body"),
        ("timestamp-good", ts_good, "timestamp", "releases-timestamp", None, "ok"),
        ("timestamp-signed-by-files-key", sign_file(key, "timestamp", "releases-timestamp", stamp, None, now=t0), "timestamp", "releases-timestamp", None, "wrong-role"),
        ("release-list-signed-by-timestamp-key", sign_file(tkey, "release-list", "releases", payload, None, now=t0), "release-list", "releases", None, "wrong-role"),
        ("timestamp-lives-too-long", seal(json.dumps(dict(json.loads(ts_good["body"]), expires="2026-11-14T10:00:00Z"), separators=(",", ":")).encode(), *tkey), "timestamp", "releases-timestamp", None, "bad-lifetime"),
        ("partner-good", sign_file(key, "partner", "partner:acme-exchange", {"name": "Acme Exchange (test)"}, None, now=t0), "partner", "partner:acme-exchange", None, "ok"),
        ("wallet-settings-good", sign_file(key, "wallet-settings", "wallet-settings", {"promotions": []}, None, now=t0), "wallet-settings", "wallet-settings", None, "ok"),
    ]
    out.mkdir(parents=True, exist_ok=True)
    keys = [pub, tpub]
    (out / "test-keys.json").write_text(json.dumps(keys, indent=1) + "\n")
    index = []
    for name, f, kind, fid, last, expect in cases:
        (out / f"{name}.json").write_text(json.dumps(f, indent=1) + "\n")
        got = "ok"
        try:
            verify((out / f"{name}.json").read_bytes(), keys, kind, fid, now, last)
        except Refused as e:
            got = e.code
        assert got == expect, f"vector {name}: expected {expect}, got {got}"
        index.append({"file": f"{name}.json", "kind": kind, "id": fid, "now": iso(now), "last_good": last, "expect": expect})
    pairs = []
    for rel_name, ts_name in (("good", "timestamp-good"), ("good-second-after-first", "timestamp-good")):
        r_ = verify((out / f"{rel_name}.json").read_bytes(), keys, "release-list", "releases", now)
        t_ = verify((out / f"{ts_name}.json").read_bytes(), keys, "timestamp", "releases-timestamp", now)
        try:
            check_fresh(r_, t_); got = "ok"
        except Refused as e:
            got = e.code
        pairs.append({"releases": f"{rel_name}.json", "timestamp": f"{ts_name}.json", "now": iso(now), "expect": got})
    assert [x["expect"] for x in pairs] == ["ok", "not-fresh"]
    (out / "fresh-pairs.json").write_text(json.dumps({"note": "check_fresh() cases (docs/SIGNED_FILES.md section 8). CLX has no value.",
                                                      "cases": pairs}, indent=1) + "\n")
    rollout = [{"install_id": i, "product": "calibre-wallet", "version": "0.3.0",
                "bucket": rollout_bucket(i, "calibre-wallet", "0.3.0")} for i in ("install-a", "install-b", "partner:acme-exchange")]
    def r(version, required=False, reason=None, stages=((0, 100),), paused=False):
        return {"version": version, "required": required, "reason": reason,
                "notes_url": f"https://github.com/BitCore77-Calibre/calibre-wallet/releases/tag/v{version}", "files": [],
                "rollout": {"start": "2026-11-04T10:00:00Z", "stages": [list(x) for x in stages], "paused": paused}}
    entries = {
        "three-channels": {"min_version": None, "channels": {"stable": r("0.3.0"), "beta": r("0.4.0-rc.1"), "edge": r("0.4.0-edge.1")}},
        "required-fix": {"min_version": None, "channels": {"stable": r("0.3.1", True, "key check fix", ((0, 1), (24, 100)))}},
        "min-version": {"min_version": "0.3.0", "channels": {"stable": r("0.3.0", stages=((0, 1), (24, 100)))}},
        "paused-stable": {"min_version": None, "channels": {"stable": r("0.3.0", paused=True), "beta": r("0.3.0-rc.2")}},
        "staged": {"min_version": None, "channels": {"stable": r("0.3.0", stages=((0, 10), (24, 50), (48, 100)))}},
    }
    asks = [("three-channels", "stable", "0.2.0"), ("three-channels", "beta", "0.2.0"), ("three-channels", "edge", "0.2.0"),
            ("three-channels", "stable", "0.3.0"), ("three-channels", "unknown", "0.2.0"), ("required-fix", "stable", "0.3.0"),
            ("min-version", "stable", "0.2.9"), ("paused-stable", "stable", "0.2.0"), ("paused-stable", "beta", "0.2.0")]
    asks += [("staged", "stable", "0.2.0", i) for i in ("install-0", "install-21", "install-a", "install-b")]
    choices = []
    for a in asks:
        name, channel, current = a[:3]
        inst = a[3] if len(a) > 3 else "install-a"
        got = choose_update(entries[name], channel, current, inst, "calibre-wallet", now)
        choices.append({"entry": name, "channel": channel, "current": current, "install_id": inst, "product": "calibre-wallet",
                        "now": iso(now), "expect": None if got is None else {k: got[k] for k in ("version", "channel", "required", "reason")}})
    assert all(not release_list_problems({"products": {"calibre-wallet": e}}) for e in entries.values())
    (out / "release-choices.json").write_text(json.dumps({"note": "choose_update() cases for every port (docs/SIGNED_FILES.md section 5). CLX has no value.",
                                                          "entries": entries, "cases": choices}, indent=1) + "\n")
    (out / "index.json").write_text(json.dumps({"format": FORMAT, "note": "PUBLIC test key (seeds 0..31 and 32..63); never use for real files. CLX has no value.",
                                                "cases": index, "rollout_buckets": rollout}, indent=1) + "\n")
    return index


# ------------------------------------------------------------------ command line

def _load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="signed_files.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--key-dir", required=True)
    k.add_argument("--role", choices=["files", "timestamp"], default="files")
    p = sub.add_parser("pubkey"); p.add_argument("--key-dir", required=True)
    s = sub.add_parser("sign"); s.add_argument("--key-dir", required=True); s.add_argument("--kind", required=True)
    s.add_argument("--id", required=True); g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--previous"); g.add_argument("--first", action="store_true")
    s.add_argument("--history", help="folder with every earlier signed file of this id (history/<id>/)")
    s.add_argument("--earlier-keys", help="after a key rotation: JSON list of the earlier public keys that signed the history")
    s.add_argument("--days", type=int); s.add_argument("payload"); s.add_argument("out")
    r = sub.add_parser("rollback"); r.add_argument("--key-dir", required=True); r.add_argument("--good", required=True)
    r.add_argument("--current", required=True); r.add_argument("--days", type=int); r.add_argument("out")
    v = sub.add_parser("verify"); v.add_argument("--keys", required=True); v.add_argument("--kind", required=True)
    v.add_argument("--id", required=True); v.add_argument("--state"); v.add_argument("file")
    sh = sub.add_parser("show"); sh.add_argument("file")
    fr = sub.add_parser("fresh", help="verify a release list and its timestamp together (exit 0 = fresh)")
    fr.add_argument("--keys", required=True); fr.add_argument("releases"); fr.add_argument("timestamp")
    ve = sub.add_parser("vectors"); ve.add_argument("out")
    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        d = Path(a.key_dir).expanduser()
        if (d / "signing-key.json").exists():
            raise SystemExit(f"{d}/signing-key.json already exists; never overwrite a signing key")
        pub = write_key(d, os.urandom(32), os.urandom(32), passphrase(confirm=True), a.role)
        print(f"key {pub['key_id']} made in {d}. Back up signing-key.json (it is encrypted); the apps build in signing-public.json.")
    elif a.cmd == "pubkey":
        print((Path(a.key_dir).expanduser() / "signing-public.json").read_text(), end="")
    elif a.cmd == "sign":
        payload = _load(a.payload)
        prev = None if a.first else _load(a.previous)
        hist = None if not a.history else [_load(str(f)) for f in sorted(Path(a.history).expanduser().glob("*.json"))]
        out = sign_file(read_key(Path(a.key_dir).expanduser(), passphrase()), a.kind, a.id, payload, prev, days=a.days, history=hist,
                       earlier_keys=_load(a.earlier_keys) if a.earlier_keys else None)
        Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
        b = json.loads(out["body"]); print(f"{a.out}: {b['kind']} {b['id']} serial {b['serial']}, expires {b['expires']}")
    elif a.cmd == "rollback":
        good, cur = _load(a.good), _load(a.current)
        gb, cb = json.loads(good["body"]), json.loads(cur["body"])
        if (gb["kind"], gb["id"]) != (cb["kind"], cb["id"]):
            raise SystemExit("the two files are for different kinds or ids")
        out = sign_file(read_key(Path(a.key_dir).expanduser(), passphrase()), cb["kind"], cb["id"], gb["payload"], cur, days=a.days, rollback=True)
        Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
        print(f"{a.out}: serial {json.loads(out['body'])['serial']} carries the payload of serial {gb['serial']}")
    elif a.cmd == "verify":
        state = Path(a.state) if a.state else None
        last = json.loads(state.read_text()).get(a.id) if state and state.exists() else None
        try:
            r = verify(Path(a.file).read_bytes(), _load(a.keys), a.kind, a.id, datetime.now(timezone.utc), last)
        except Refused as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1
        if state:
            all_state = json.loads(state.read_text()) if state.exists() else {}
            all_state[a.id] = {"serial": r["serial"], "sha256": r["sha256"], "key_id": r["key_id"]}
            state.write_text(json.dumps(all_state, indent=1) + "\n")
        print(json.dumps(r["payload"], indent=1, ensure_ascii=False))
    elif a.cmd == "fresh":
        keys, now = _load(a.keys), datetime.now(timezone.utc)
        try:
            r = verify(Path(a.releases).read_bytes(), keys, "release-list", "releases", now)
            t = verify(Path(a.timestamp).read_bytes(), keys, "timestamp", "releases-timestamp", now)
            check_fresh(r, t)
        except Refused as e:
            print(f"not fresh: {e}", file=sys.stderr)
            return 1
        print(f"fresh: release list serial {r['serial']} (expires {r['expires']}), timestamp expires {t['expires']}")
    elif a.cmd == "show":
        print(json.dumps(json.loads(_load(a.file)["body"]), indent=1, ensure_ascii=False))
    elif a.cmd == "vectors":
        print(f"{len(vectors(Path(a.out)))} vectors written to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
