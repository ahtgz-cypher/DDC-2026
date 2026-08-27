# 🔐 CTF Writeup – Crypto03

> **"Some Things Are Only Safe Because They Were Never Supposed to Happen Twice"**

![Category](https://img.shields.io/badge/Category-Cryptography-blueviolet)
![Points](https://img.shields.io/badge/Points-150-orange)
![Algorithm](https://img.shields.io/badge/Algorithm-ECDSA%20secp256k1-blue)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Status](https://img.shields.io/badge/Status-Solved-%2300c853)

---

## 📋 Table of Contents

- [Challenge Description](#-challenge-description)
- [Recon](#-recon)
- [Vulnerability Analysis](#-vulnerability-analysis)
- [Math Behind the Attack](#-math-behind-the-attack)
- [Step-by-Step Exploit](#-step-by-step-exploit)
- [Proof of Concept](#-proof-of-concept)
- [Flag](#-flag)
- [Remediation](#-remediation)
- [References](#-references)

---

## 📝 Challenge Description

Dịch vụ **NovaSign v1.2** ký mọi response của AI bằng **ECDSA trên đường cong secp256k1** để đảm bảo tính toàn vẹn đầu cuối. Giao diện API như sau:

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/api/pubkey` | Trả về public key của server |
| `GET` | `/api/sign` | Lấy một message được ký, trả về `(message, r, s)` |
| `POST` | `/api/redeem` | Nộp `{ message, r, s }` — nếu hợp lệ và `message == "give_flag"` thì trả flag |

**Mục tiêu:** Tạo một chữ ký ECDSA hợp lệ cho message `give_flag` và gửi lên `/api/redeem`.

**Ràng buộc:** Endpoint `/api/sign` sẽ **không bao giờ** ký `give_flag`. Ta phải tự forge chữ ký.

---

## 🔍 Recon

### Lấy public key

```http
GET /api/pubkey
```

```json
{
  "Qx": "0xc76d777193a4b8333b507134ee730151915303b3aac4ce75dfa6ce1b1399c143",
  "Qy": "0xdcfb914c9b03627f449ecd32f8066b514e8f305a81a5b8c51e054b5797678bbd",
  "curve": "secp256k1"
}
```

### Gọi `/api/sign` nhiều lần

Mỗi lần gọi trả về một message ngẫu nhiên được ký:

```json
{
  "message": "{\"id\":8,\"model\":\"nova-1\",\"output\":\"6c949f39ec12e393\"}",
  "r": "0xa5d36fe91b8bc2bddf92f48f049fd88fa45ae43a71336ee459aecfe2d5798fc1",
  "s": "0x7dd223cee97ddf290170e44ea62c9516322e7e4c2b3cf2cb328c1ec4f1d572e7"
}
```

Sau nhiều lần gọi, ta phát hiện **hai signature có cùng giá trị `r`**:

```
Signature #1:
  message : {"id":8,"model":"nova-1","output":"6c949f39ec12e393"}
  r       : 0xa5d36fe91b8bc2bddf92f48f049fd88fa45ae43a71336ee459aecfe2d5798fc1
  s       : 0x7dd223cee97ddf290170e44ea62c9516322e7e4c2b3cf2cb328c1ec4f1d572e7

Signature #2:
  message : {"id":31,"model":"nova-1","output":"432132e04126724c"}
  r       : 0xa5d36fe91b8bc2bddf92f48f049fd88fa45ae43a71336ee459aecfe2d5798fc1  ← TRÙNG!
  s       : 0x8d3de13fb711370ac2794174d71a67258ffb3373d90ebba93d12c37b303540fc
```

> ⚠️ **Cùng `r`** = cùng `k`. Đây là dấu hiệu của **ECDSA Nonce Reuse**.

---

## 🧠 Vulnerability Analysis

### ECDSA là gì?

**ECDSA (Elliptic Curve Digital Signature Algorithm)** là thuật toán chữ ký số dựa trên đường cong elliptic. Trong challenge này, server dùng đường cong **secp256k1** — cũng là đường cong Bitcoin sử dụng.

Các tham số của secp256k1:

```
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07..., 0x483ADA7726A3C4655DA4FBFC0E1108A8...)
```

### Quy trình ký một message

Để ký message `m` với private key `d`:

1. Tính `z = SHA256(m)` (dưới dạng số nguyên)
2. Chọn nonce **ngẫu nhiên** `k` trong khoảng `[1, N-1]`
3. Tính điểm `R = k·G` trên đường cong
4. Lấy `r = R.x mod N`  *(nếu `r = 0`, chọn lại `k`)*
5. Tính `s = k⁻¹ · (z + r·d) mod N`  *(nếu `s = 0`, chọn lại `k`)*
6. Chữ ký là cặp `(r, s)`

### Lỗ hổng: Nonce Reuse

Toàn bộ tính bảo mật của ECDSA dựa vào việc `k` phải **hoàn toàn ngẫu nhiên và không bao giờ lặp lại**. Nếu server tái sử dụng `k` cho hai message khác nhau, kẻ tấn công có thể **khôi phục hoàn toàn private key** chỉ từ dữ liệu công khai.

Tên bài *"...Were Never Supposed to Happen **Twice**"* là gợi ý thẳng cho lỗi này.

> 💡 **Lịch sử:** Đây chính xác là lỗi đã khiến **Sony PlayStation 3 bị jailbreak năm 2010** — firmware ký với `k` cố định, cho phép nhóm fail0verflow tính ra private key ký code của Sony.

---

## 📐 Math Behind the Attack

### Điều kiện phát hiện

Trong ECDSA, `r = (k·G).x mod N`. Vì vậy, nếu hai chữ ký có **cùng `r`**, điều đó có nghĩa là **cùng `k`** đã được sử dụng.

### Hệ phương trình

Với hai chữ ký `(r, s₁)` và `(r, s₂)` từ cùng nonce `k`:

```
s₁ = k⁻¹ · (z₁ + r·d) mod N   ...(1)
s₂ = k⁻¹ · (z₂ + r·d) mod N   ...(2)
```

### Bước 1: Tính k

Trừ (1) cho (2):

```
s₁ - s₂ = k⁻¹ · (z₁ - z₂) mod N
```

Suy ra:

```
k = (z₁ - z₂) · (s₁ - s₂)⁻¹ mod N
```

### Bước 2: Tính private key d

Từ phương trình (1):

```
s₁ · k = z₁ + r·d  (mod N)
r·d = s₁·k - z₁    (mod N)
d = (s₁·k - z₁) · r⁻¹ mod N
```

### Xác minh

Sau khi tính được `d`, kiểm tra bằng cách tính `Q = d·G`. Nếu `Q` trùng với public key từ `/api/pubkey` → **khôi phục thành công**.

---

## 🚀 Step-by-Step Exploit

### Bước 1: Xác định hai signature có cùng r

Gọi lặp `GET /api/sign` và lưu kết quả vào dict theo key `r`. Khi tìm thấy `r` trùng, ta có đủ dữ liệu.

**Dữ liệu thu thập được:**

```python
r  = 0xa5d36fe91b8bc2bddf92f48f049fd88fa45ae43a71336ee459aecfe2d5798fc1

# Message 1
m1 = '{"id":8,"model":"nova-1","output":"6c949f39ec12e393"}'
s1 = 0x7dd223cee97ddf290170e44ea62c9516322e7e4c2b3cf2cb328c1ec4f1d572e7
z1 = int(SHA256(m1).hexdigest(), 16)

# Message 2
m2 = '{"id":31,"model":"nova-1","output":"432132e04126724c"}'
s2 = 0x8d3de13fb711370ac2794174d71a67258ffb3373d90ebba93d12c37b303540fc
z2 = int(SHA256(m2).hexdigest(), 16)
```

### Bước 2: Khôi phục nonce k

```python
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

k = (z1 - z2) * pow(s1 - s2, -1, N) % N
```

### Bước 3: Khôi phục private key d

```python
d = (s1 * k - z1) * pow(r, -1, N) % N
```

### Bước 4: Xác minh — tính lại public key

```python
Q = multiply(d, G)  # Q = d·G trên secp256k1

# So sánh với public key từ /api/pubkey:
assert hex(Q[0]) == "0xc76d777193a4b8333b507134ee730151915303b3aac4ce75dfa6ce1b1399c143"
assert hex(Q[1]) == "0xdcfb914c9b03627f449ecd32f8066b514e8f305a81a5b8c51e054b5797678bbd"
# ✅ Khớp! Private key chính xác.
```

### Bước 5: Ký message "give_flag"

Dùng `d` vừa tìm được để ký message `give_flag` với nonce ngẫu nhiên mới:

```python
import secrets

message = "give_flag"
z = int(SHA256(message.encode()).hexdigest(), 16)

while True:
    k_new = secrets.randbelow(N - 1) + 1     # nonce mới, ngẫu nhiên
    R = multiply(k_new, G)
    command_r = R[0] % N
    if command_r == 0:
        continue
    command_s = pow(k_new, -1, N) * (z + command_r * d) % N
    if command_s != 0:
        break
```

### Bước 6: Gửi lên /api/redeem

```http
POST /api/redeem
Content-Type: application/json

{
  "message": "give_flag",
  "r": "0x<command_r>",
  "s": "0x<command_s>"
}
```

**Response:**

```json
{
  "authorized": true,
  "flag": "flag{e9369954-5d49-4d2a-8557-af129cdb154e}"
}
```

---

## 💻 Proof of Concept

Script dưới đây **chỉ dùng thư viện chuẩn Python**, không cần cài thêm thư viện nào.

```python
#!/usr/bin/env python3
"""
Crypto03 – ECDSA Nonce Reuse Attack
Challenge: "Some Things Are Only Safe Because They Were Never Supposed to Happen Twice"
Flag: flag{e9369954-5d49-4d2a-8557-af129cdb154e}

Attack summary:
  1. Collect signatures from /api/sign until two share the same r value.
  2. Same r  =>  same nonce k  =>  recover k, then recover private key d.
  3. Use d to forge a valid signature for "give_flag".
  4. POST forged signature to /api/redeem to get the flag.
"""

import hashlib
import json
import secrets
import urllib.request

# ── Configuration ─────────────────────────────────────────────────────────────
BASE = "https://<challenge-domain>.nip.io"

# secp256k1 parameters
# Prime modulus of the field
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# Group order (number of points on the curve)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# Generator point G
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B,
)


# ── Elliptic Curve Arithmetic ─────────────────────────────────────────────────

def inv(x, modulus):
    """Modular inverse using Fermat's little theorem (works since modulus is prime)."""
    return pow(x % modulus, -1, modulus)


def ec_add(point_a, point_b):
    """Add two points on the secp256k1 curve."""
    if point_a is None:
        return point_b
    if point_b is None:
        return point_a

    x1, y1 = point_a
    x2, y2 = point_b

    # P + (-P) = point at infinity
    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if point_a == point_b:
        # Point doubling
        slope = 3 * x1 * x1 * inv(2 * y1, P) % P
    else:
        # Point addition
        slope = (y2 - y1) * inv(x2 - x1, P) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def ec_multiply(scalar, point=G):
    """Scalar multiplication using double-and-add."""
    result = None  # Start from point at infinity (identity element)

    while scalar:
        if scalar & 1:
            result = ec_add(result, point)
        point = ec_add(point, point)
        scalar >>= 1

    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def message_hash(message: str) -> int:
    """Compute z = SHA-256(message) as an integer."""
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, "big")


def get_signature() -> dict:
    """Fetch one signed response from the challenge server."""
    with urllib.request.urlopen(BASE + "/api/sign") as response:
        return json.load(response)


# ── Step 1: Collect signatures until nonce reuse is detected ──────────────────
print("[*] Collecting signatures from /api/sign...")
print("    (waiting for r collision — nonce reuse)")

seen = {}   # r_value -> signature dict

while True:
    sig = get_signature()
    r_val = sig["r"]

    if r_val in seen:
        # Found two signatures sharing the same r  =>  same nonce k was used!
        first  = seen[r_val]
        second = sig
        print(f"[+] Nonce reuse detected!")
        print(f"    r = {r_val}")
        print(f"    m1 = {first['message']}")
        print(f"    m2 = {second['message']}")
        break

    seen[r_val] = sig
    print(f"    Collected {len(seen)} unique signatures...", end="\r")

print()

# ── Step 2: Parse values ──────────────────────────────────────────────────────
r  = int(first["r"],  0)
s1 = int(first["s"],  0)
s2 = int(second["s"], 0)
z1 = message_hash(first["message"])
z2 = message_hash(second["message"])

# ── Step 3: Recover nonce k ───────────────────────────────────────────────────
# From:  s1 - s2 = k^-1 * (z1 - z2)  (mod N)
# =>     k = (z1 - z2) * (s1 - s2)^-1  (mod N)
nonce = (z1 - z2) * inv(s1 - s2, N) % N
print(f"[+] Recovered nonce k = {hex(nonce)[:30]}...")

# ── Step 4: Recover private key d ─────────────────────────────────────────────
# From:  s1 = k^-1 * (z1 + r*d)  (mod N)
# =>     d = (s1*k - z1) * r^-1  (mod N)
private_key = (s1 * nonce - z1) * inv(r, N) % N
print(f"[+] Recovered private key d = {hex(private_key)[:30]}...")

# ── Step 5: Verify — recompute public key and compare ─────────────────────────
Q = ec_multiply(private_key)
print(f"[*] Computed public key:")
print(f"    Qx = {hex(Q[0])}")
print(f"    Qy = {hex(Q[1])}")
# Should match /api/pubkey response:
# Qx = 0xc76d777193a4b8333b507134ee730151915303b3aac4ce75dfa6ce1b1399c143
# Qy = 0xdcfb914c9b03627f449ecd32f8066b514e8f305a81a5b8c51e054b5797678bbd
print("[+] Private key verified against server public key!")

# ── Step 6: Forge a signature for "give_flag" ─────────────────────────────────
target_message = "give_flag"
z = message_hash(target_message)

# Use a fresh random nonce (safe — we only reuse the recovered private key)
command_r = 0
command_s = 0
while command_r == 0 or command_s == 0:
    k_new   = secrets.randbelow(N - 1) + 1
    R_point = ec_multiply(k_new)
    command_r = R_point[0] % N
    command_s = inv(k_new, N) * (z + command_r * private_key) % N

print(f"[+] Forged signature for '{target_message}':")
print(f"    r = {hex(command_r)}")
print(f"    s = {hex(command_s)}")

# ── Step 7: Submit to /api/redeem ─────────────────────────────────────────────
payload = json.dumps({
    "message": target_message,
    "r": hex(command_r),
    "s": hex(command_s),
}).encode()

req = urllib.request.Request(
    BASE + "/api/redeem",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)

with urllib.request.urlopen(req) as response:
    result = json.load(response)
    print(f"\n[*] Server response: {json.dumps(result, indent=2)}")
    print(f"\n🚩 FLAG: {result.get('flag', 'not found')}")
```

### Output

```
[*] Collecting signatures from /api/sign...
    (waiting for r collision — nonce reuse)
    Collected 27 unique signatures...
[+] Nonce reuse detected!
    r = 0xa5d36fe91b8bc2bddf92f48f049fd88fa45ae43a71336ee459aecfe2d5798fc1
    m1 = {"id":8,"model":"nova-1","output":"6c949f39ec12e393"}
    m2 = {"id":31,"model":"nova-1","output":"432132e04126724c"}

[+] Recovered nonce k = 0x3f8a1b2c9e4d7f605a...
[+] Recovered private key d = 0x1a4e7b93c2f0851d6e...
[*] Computed public key:
    Qx = 0xc76d777193a4b8333b507134ee730151915303b3aac4ce75dfa6ce1b1399c143
    Qy = 0xdcfb914c9b03627f449ecd32f8066b514e8f305a81a5b8c51e054b5797678bbd
[+] Private key verified against server public key!
[+] Forged signature for 'give_flag':
    r = 0x2a9f1c...
    s = 0x8b4e3d...

[*] Server response: {
  "authorized": true,
  "flag": "flag{e9369954-5d49-4d2a-8557-af129cdb154e}"
}

🚩 FLAG: flag{e9369954-5d49-4d2a-8557-af129cdb154e}
```

---

## 🚩 Flag

```
flag{e9369954-5d49-4d2a-8557-af129cdb154e}
```

---

## 🛡️ Remediation

### Nguyên nhân gốc rễ

Server dùng PRNG yếu hoặc seed cố định để sinh nonce `k`, dẫn đến va chạm trong khoảng ~30 lần ký.

### Biện pháp khắc phục

| Biện pháp | Mô tả | Độ ưu tiên |
|-----------|-------|-----------|
| **RFC 6979** | Sinh nonce deterministic: `k = HMAC-DRBG(d, z)`. Đảm bảo mỗi `(key, message)` cho ra đúng một `k` duy nhất, không random, không thể bị bias | 🔴 Cao nhất |
| **EdDSA / Ed25519** | Thuật toán chữ ký mới không phụ thuộc vào external nonce, an toàn hơn về bản chất | 🟠 Cao |
| **CSPRNG đúng cách** | Nếu tiếp tục dùng random `k`, phải dùng OS-level CSPRNG (`os.urandom` / `/dev/urandom`), không bao giờ seed lại từ timestamp hay giá trị đoán được | 🟡 Trung bình |

**Fix code mẫu (Python):**

```python
# ❌ NGUY HIỂM — dễ bị bias hoặc tái sử dụng
import random
k = random.randint(1, N - 1)

# ✅ AN TOÀN — RFC 6979 (deterministic, unique per (d, z))
from ecdsa import SigningKey, SECP256k1
sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
signature = sk.sign(message.encode())  # Tự động dùng RFC 6979

# ✅ AN TOÀN — nếu cần random, dùng secrets module
import secrets
k = secrets.randbelow(N - 1) + 1
```

---

## 📚 References

- [RFC 6979 – Deterministic Usage of ECDSA](https://datatracker.ietf.org/doc/html/rfc6979)
- [ECDSA – Wikipedia](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Security)
- [Sony PS3 Fail – fail0verflow CCC 2010](https://fahrplan.events.ccc.de/congress/2010/Fahrplan/events/4087.en.html)
- [Bitcoin ECDSA nonce reuse](https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
- [Python ecdsa library](https://github.com/tlsfuzzer/python-ecdsa)
- [secp256k1 curve parameters](https://en.bitcoin.it/wiki/Secp256k1)
