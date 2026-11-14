"""Zigbee NWK decryption with configured network keys: AES-128 CCM* (pure Python).

Only keys supplied by the user are used (--keys FILE). Zigbee secures NWK
frames with the network key at security level 5 (ENC-MIC-32):

    nonce = sender IEEE address (8, as sent) | frame counter (4, LE) | security control
    a     = NWK header | auxiliary security header      (authenticated, not encrypted)
    m     = NWK payload                                  (encrypted)
    MIC   = 4 bytes

The security level field is sent as 0 and must be replaced by the real level
(5) in the nonce and in a. A wrong key fails the MIC check, so several keys can
be tried; the key that works is remembered per key sequence number.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import OrderedDict
from pathlib import Path

DEFAULT_SECURITY_LEVEL = 5
MIC_LENGTH = {0: 0, 1: 4, 2: 8, 3: 16, 4: 0, 5: 4, 6: 8, 7: 16}


# ------------------------------------------------------------------- AES-128
def _make_tables():
    sbox = [0] * 256
    p = q = 1
    while True:  # walk GF(2^8) by generator 3; q = p^-1
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    te = [[0] * 256 for _ in range(4)]
    for i, s in enumerate(sbox):
        s2 = ((s << 1) ^ (0x1B if s & 0x80 else 0)) & 0xFF
        s3 = s2 ^ s
        te[0][i] = (s2 << 24) | (s << 16) | (s << 8) | s3
        te[1][i] = (s3 << 24) | (s2 << 16) | (s << 8) | s
        te[2][i] = (s << 24) | (s3 << 16) | (s2 << 8) | s
        te[3][i] = (s << 24) | (s << 16) | (s3 << 8) | s2
    return sbox, te


_SBOX, (_TE0, _TE1, _TE2, _TE3) = _make_tables()


class AES128:
    """AES-128 forward cipher (all CCM* needs)."""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 needs a 16-byte key")
        w = [int.from_bytes(key[i : i + 4], "big") for i in range(0, 16, 4)]
        rcon = 1
        for i in range(4, 44):
            t = w[i - 1]
            if i % 4 == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = (
                    (_SBOX[t >> 24] << 24)
                    | (_SBOX[(t >> 16) & 0xFF] << 16)
                    | (_SBOX[(t >> 8) & 0xFF] << 8)
                    | _SBOX[t & 0xFF]
                ) ^ (rcon << 24)
                rcon = ((rcon << 1) ^ (0x1B if rcon & 0x80 else 0)) & 0xFF
            w.append(w[i - 4] ^ t)
        self._rk = w

    def encrypt_block(self, block: bytes) -> bytes:
        rk = self._rk
        s0 = int.from_bytes(block[0:4], "big") ^ rk[0]
        s1 = int.from_bytes(block[4:8], "big") ^ rk[1]
        s2 = int.from_bytes(block[8:12], "big") ^ rk[2]
        s3 = int.from_bytes(block[12:16], "big") ^ rk[3]
        for r in range(4, 40, 4):
            t0 = _TE0[s0 >> 24] ^ _TE1[(s1 >> 16) & 255] ^ _TE2[(s2 >> 8) & 255] ^ _TE3[s3 & 255] ^ rk[r]
            t1 = _TE0[s1 >> 24] ^ _TE1[(s2 >> 16) & 255] ^ _TE2[(s3 >> 8) & 255] ^ _TE3[s0 & 255] ^ rk[r + 1]
            t2 = _TE0[s2 >> 24] ^ _TE1[(s3 >> 16) & 255] ^ _TE2[(s0 >> 8) & 255] ^ _TE3[s1 & 255] ^ rk[r + 2]
            t3 = _TE0[s3 >> 24] ^ _TE1[(s0 >> 16) & 255] ^ _TE2[(s1 >> 8) & 255] ^ _TE3[s2 & 255] ^ rk[r + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        S = _SBOX
        out = []
        for a, b, c, d, k in (
            (s0, s1, s2, s3, rk[40]),
            (s1, s2, s3, s0, rk[41]),
            (s2, s3, s0, s1, rk[42]),
            (s3, s0, s1, s2, rk[43]),
        ):
            v = ((S[a >> 24] << 24) | (S[(b >> 16) & 255] << 16) | (S[(c >> 8) & 255] << 8) | S[d & 255]) ^ k
            out.append(v.to_bytes(4, "big"))
        return b"".join(out)


# ---------------------------------------------------------------------- CCM*
def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _blocks(data: bytes):
    data = data + b"\x00" * ((-len(data)) % 16)
    for i in range(0, len(data), 16):
        yield data[i : i + 16]


def _cbc_mac(aes: AES128, nonce: bytes, a: bytes, m: bytes, mic_len: int) -> bytes:
    flags = (0x40 if a else 0) | (((mic_len - 2) // 2) << 3) | 1  # L = 2
    x = aes.encrypt_block(bytes([flags]) + nonce + len(m).to_bytes(2, "big"))
    if a:
        for blk in _blocks(len(a).to_bytes(2, "big") + a):
            x = aes.encrypt_block(_xor(x, blk))
    for blk in _blocks(m):
        x = aes.encrypt_block(_xor(x, blk))
    return x[:mic_len]


def _ctr(aes: AES128, nonce: bytes, data: bytes, first: int) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 16):
        s = aes.encrypt_block(b"\x01" + nonce + (first + i // 16).to_bytes(2, "big"))
        out += _xor(data[i : i + 16], s)
    return bytes(out)


def ccm_star_encrypt(key: bytes | AES128, nonce: bytes, a: bytes, m: bytes, mic_len: int = 4) -> bytes:
    """Returns ciphertext | encrypted MIC (13-byte nonce, L = 2)."""
    aes = key if isinstance(key, AES128) else AES128(key)
    tag = _cbc_mac(aes, nonce, a, m, mic_len)
    return _ctr(aes, nonce, m, 1) + _ctr(aes, nonce, tag, 0)


def ccm_star_decrypt(key: bytes | AES128, nonce: bytes, a: bytes, c: bytes, mic_len: int = 4) -> bytes | None:
    """Plaintext of ciphertext | MIC, or None when the MIC does not verify."""
    aes = key if isinstance(key, AES128) else AES128(key)
    if len(c) < mic_len:
        return None
    m = _ctr(aes, nonce, c[: len(c) - mic_len], 1)
    tag = _ctr(aes, nonce, c[len(c) - mic_len :], 0)
    return m if _cbc_mac(aes, nonce, a, m, mic_len) == tag else None


# ------------------------------------------------------------- NWK frames
def nwk_security_parts(data: bytes, n, src64: bytes | None = None, level: int = DEFAULT_SECURITY_LEVEL):
    """(nonce, a, ciphertext|MIC, mic_len) for a secured NWK frame `data` decoded as `n`
    (mac.NwkFrame), or None when the sender's IEEE address is unknown."""
    h = n.header_len
    sc = data[h]
    lvl = sc & 7 or level
    sc_real = (sc & ~7) | lvl
    if sc & 0x20:
        src64 = data[h + 5 : h + 13]
    if src64 is None or len(src64) != 8:
        return None
    nonce = src64 + data[h + 1 : h + 5] + bytes([sc_real])
    end = h + n.aux_len
    a = data[:h] + bytes([sc_real]) + data[h + 1 : end]
    return nonce, a, data[end:], MIC_LENGTH[lvl]


def encrypt_nwk(key: bytes, header: bytes, aux: bytes, payload: bytes, level: int = DEFAULT_SECURITY_LEVEL) -> bytes:
    """Build a secured NWK frame (header | aux | ciphertext | MIC) the way a Zigbee
    device does; `aux` must carry the extended nonce. Used by tests and the example."""
    sc_real = (aux[0] & ~7) | level
    nonce = aux[5:13] + aux[1:5] + bytes([sc_real])
    a = header + bytes([sc_real]) + aux[1:]
    return header + aux + ccm_star_encrypt(key, nonce, a, payload, MIC_LENGTH[level])


class KeyRing:
    """Configured network keys. decrypt_nwk() tries the key that last worked for
    the frame's key sequence number first, then the others."""

    def __init__(self, keys: list[bytes]):
        seen: list[bytes] = []
        for k in keys:
            for variant in (k, k[::-1]):  # some tools show keys byte-reversed
                if variant not in seen:
                    seen.append(variant)
        self.keys = seen
        self.configured = len({k for k in keys})
        self._aes = [AES128(k) for k in seen]
        self._by_seq: dict[int | None, int] = {}
        self._cache: OrderedDict[bytes, bytes | None] = OrderedDict()
        self.ok = 0
        self.failed = 0

    def __bool__(self) -> bool:
        return bool(self.keys)

    def decrypt_nwk(self, data: bytes, n, src64: bytes | None = None) -> bytes | None:
        """Plaintext NWK payload of the secured frame `data` (decoded as `n`), or None."""
        if not n.secured or not self.keys:
            return None
        if data in self._cache:
            self._cache.move_to_end(data)
            return self._cache[data]
        parts = nwk_security_parts(data, n, src64)
        result = None
        if parts and parts[3]:
            nonce, a, c, mic_len = parts
            first = self._by_seq.get(n.key_seq)
            order = ([first] if first is not None else []) + [i for i in range(len(self._aes)) if i != first]
            for i in order:
                m = ccm_star_decrypt(self._aes[i], nonce, a, c, mic_len)
                if m is not None:
                    self._by_seq[n.key_seq] = i
                    result = m
                    break
        if result is None:
            self.failed += 1
        else:
            self.ok += 1
        self._cache[data] = result
        if len(self._cache) > 512:
            self._cache.popitem(last=False)
        return result


# ---------------------------------------------------------------- key files
_HEX32 = re.compile(r"(?:0x)?((?:[0-9a-fA-F]{2}[:\-\s]?){15}[0-9a-fA-F]{2})")


def _key_from_text(text: str) -> bytes | None:
    m = _HEX32.fullmatch(text.strip().strip("'\""))
    return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", m.group(1))) if m else None


def _key_from_value(v) -> bytes | None:
    if isinstance(v, str):
        return _key_from_text(v)
    if isinstance(v, list) and len(v) == 16 and all(isinstance(x, int) and 0 <= x <= 255 for x in v):
        return bytes(v)
    return None


def load_keys(path: str | Path) -> list[bytes]:
    """Network keys from a file of the user's own configuration:

    * text: one key per line, 32 hex digits (':' '-' or spaces allowed, '#' comments)
    * JSON: "hex", ["hex", ...], {"network_key": "hex" | [16 ints]} or {"keys": [...]}
    * zigbee2mqtt configuration.yaml: network_key: [1, 3, 5, ...] (inline or as a list)
    """
    text = Path(path).read_text(encoding="utf-8")
    keys: list[bytes] = []

    def add(k: bytes | None) -> None:
        if k and k not in keys:
            keys.append(k)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if data is not None:
        items = data if isinstance(data, list) and not _key_from_value(data) else [data]
        for item in items:
            if isinstance(item, dict):
                for name in ("network_key", "key", "nwk_key"):
                    add(_key_from_value(item.get(name)))
                for v in item.get("keys", []):
                    add(_key_from_value(v))
            else:
                add(_key_from_value(item))
        return keys
    m = re.search(r"^[ \t]*network_key[ \t]*:[ \t]*(.*)$", text, re.M)
    if m:
        value = m.group(1).split("#")[0].strip()
        if value.startswith("["):
            add(_key_from_value([int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", value)]))
        elif value:
            add(_key_from_text(value))
        else:  # block list on the following lines: "  - 1"
            nums = []
            for line in text[m.end() :].splitlines()[1:]:
                item = re.match(r"^\s*-\s*(0x[0-9a-fA-F]+|\d+)\s*$", line)
                if not item:
                    break
                nums.append(int(item.group(1), 0))
            add(_key_from_value(nums))
        return keys
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if line:
            add(_key_from_text(line))
    return keys


def key_fingerprint(key: bytes) -> str:
    """Short, non-reversible label to tell keys apart in messages."""
    return hashlib.sha256(key).hexdigest()[:8]


def load_keyring(path: str | None) -> KeyRing | None:
    """KeyRing from --keys PATH or the ZBDEMOD_KEYS environment variable (a path)."""
    path = path or os.environ.get("ZBDEMOD_KEYS")
    if not path:
        return None
    keys = load_keys(path)
    if not keys:
        raise SystemExit(f"no network key found in {path}")
    return KeyRing(keys)
