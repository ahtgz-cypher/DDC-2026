# [CTF Writeup] OSINT Challenge 1: Operation: Ghost Researcher

**Category:** OSINT (Open Source Intelligence)
**Points:** 56
**Target Subject:** Nguyễn Minh Khoa — tự xưng là nhà nghiên cứu AI (PhD candidate)
**Objective:** Lần theo digital footprint từ các nguồn thông tin công khai để tìm credential bị rò rỉ.

---

## 1. Tổng quan

Khác với những challenge trước, challenge này không yêu cầu khai thác trực tiếp một lỗ hổng trên server. Thay vào đó, mục tiêu là **thu thập và liên kết các thông tin công khai** để lần theo digital footprint của một người dùng.

Đối tượng được cung cấp là **Nguyễn Minh Khoa**, được giới thiệu là một PhD candidate tại **Vietnam National Cyber Lab**.

Ban đầu, mình chỉ có một vài thông tin khá chung:

* Đối tượng gần đây có đăng một bài nghiên cứu lên **arXiv**, thuộc chuyên mục `cs.LG`.
* Có hoạt động trên **X (Twitter)**.
* Có tài khoản **GitHub** để chia sẻ mã nguồn nghiên cứu.
* Có khả năng sử dụng **Pastebin** để lưu trữ các ghi chú nghiên cứu.

Điểm bắt đầu của challenge là:

```text
https://<INSTANCE_ID>.222.255.138.122.nip.io/arxiv/
```

Nhìn vào các manh mối này, mình xác định hướng điều tra sẽ là:

```text
arXiv
  ↓
X / Twitter
  ↓
GitHub
  ↓
Pastebin
  ↓
Credential
  ↓
Base64 Decode
  ↓
Flag
```

Điểm thú vị của challenge nằm ở chỗ không có một bước nào quá khó. Vấn đề là phải **xâu chuỗi đúng các thông tin tưởng như rời rạc này với nhau**.

---

## 2. Quá trình điều tra

### Bước 1 – Tìm kiếm trên arXiv

Mình bắt đầu từ trang `/arxiv/` được cung cấp.

Tại đây có danh sách các bài nghiên cứu thuộc nhóm **Computer Science → Machine Learning (cs.LG)**. Sau khi tìm kiếm theo thông tin của đối tượng, mình tìm thấy một bài báo phù hợp:

```text
arXiv:2605.99847 [cs.LG]
```

**Title:**

> *Efficient Neural Architecture Search via Phantom Gradient Descent*

**Authors:**

* Nguyễn Minh Khoa
* Trần Đức Anh
* Sarah Mitchell

Bài báo cũng cung cấp thêm một số thông tin về tác giả:

```text
Nguyễn Minh Khoa (corresponding author)
PhD candidate, Vietnam National Cyber Lab

X (Twitter): @khoa_neuralnet

Contact: khoa.nguyen [at] vncyber-lab.example

Code, pre-trained weights and search logs are available
via the author's GitHub, linked from his X profile.
```

Đây là manh mối đầu tiên thực sự hữu ích.

Từ bài báo, mình thu được username trên X:

```text
@khoa_neuralnet
```

Như vậy, thay vì tiếp tục tìm kiếm một cách ngẫu nhiên, mình có một điểm tiếp theo khá rõ ràng.

---

## 3. Bước 2 – Theo dấu tài khoản X

Mình truy cập profile:

```text
/x/khoa_neuralnet
```

Thông tin trên profile khớp với đối tượng ban đầu:

```text
Nguyễn Minh Khoa
@khoa_neuralnet
```

Đáng chú ý nhất là **bio của tài khoản có liên kết tới GitHub**:

```text
github.com/minhkhoa-ai
```

Tuy nhiên, trước khi chuyển sang GitHub, mình kiểm tra timeline để xem tài khoản này có để lại thêm manh mối nào không.

Một bài đăng ngày **14/05** viết:

> *"Pushed the latest experiment notes to a quick paste — easier to share than running a docs site. Repo README has the link if you want to peek."*

Đây là một manh mối khá rõ.

Bài đăng cho biết:

1. Đối tượng có lưu experiment notes trên một trang paste.
2. Link tới trang paste không được đặt trực tiếp trong bài đăng.
3. Link nằm trong `README` của repository.

Như vậy, GitHub không chỉ là một tài khoản liên quan mà còn có khả năng chứa **đường dẫn trực tiếp tới bước tiếp theo**.

---

## 4. Bước 3 – Kiểm tra GitHub Repository

Mình truy cập:

```text
/gh/minhkhoa-ai
```

Trong danh sách repository, repository được ghim có tên:

```text
minhkhoa-ai/phantom-gradient-descent
```

Tên repository cũng trùng với chủ đề của bài nghiên cứu trên arXiv, vì vậy có thể xác nhận khá chắc rằng đây là repository của đúng đối tượng.

Mình mở `README.md` và tìm phần liên quan đến experiment notes.

Trong README có đoạn:

```markdown
## 📓 Experiment Notes

Full experiment logs, hyper-parameter sweeps and one-off configurations
are kept in a shared workspace paste rather than cluttering this repo:

🔗 Internal research notes (Pastebin, unlisted):
https://pastebin.com/r4j92myw
```

Đến đây, chuỗi manh mối đã khá rõ:

```text
Nguyễn Minh Khoa
       ↓
arXiv
       ↓
@khoa_neuralnet
       ↓
GitHub: minhkhoa-ai
       ↓
phantom-gradient-descent
       ↓
README.md
       ↓
Pastebin
```

Mình thu được Pastebin ID:

```text
r4j92myw
```

---

## 5. Bước 4 – Kiểm tra Pastebin

Mình truy cập paste:

```text
/p/r4j92myw
```

Tiêu đề của paste là:

```text
PGD Research Notes — Internal
```

Ngay phần đầu tài liệu đã có cảnh báo:

```text
# Phantom Gradient Descent — Internal Research Notes

# Author: Nguyễn Minh Khoa
# Date  : 2026-05-14
# Status: CONFIDENTIAL — internal use only
```

Nội dung bên dưới chủ yếu là log của các lần chạy thử nghiệm:

```text
Run #47 │ CIFAR-10        │ 50 epochs  │ lr=0.025 │ acc=97.42%  ✓
Run #48 │ ImageNet (10%)  │ 100 epochs │ lr=0.012 │ top1=76.8%  ✓
Run #49 │ NAS-Bench-201   │ search     │ 0.3 GPU-d │ best       ✓
```

Những thông tin này chưa có gì đặc biệt.

Tuy nhiên, khi kéo xuống dưới, mình thấy một section có tên:

```text
## API tokens (rotate before public release!)
```

Bên trong có:

```text
wandb_api_key = "wk-3f8a9b2c1d4e5f6a7b8c9d0e"
hf_token      = "hf_QwErTyUiOpAsDfGhJkLzXcVbNm"
```

Hai giá trị này được đánh dấu là `dummy`, nên có vẻ không phải mục tiêu chính.

Ngay bên dưới mới là phần đáng chú ý:

```text
# Project master credential — base64-encoded so it doesn't trip secret scanners

master_key_b64 = "ZmxhZ3thN2UzMmE0Mi1hY2NjLTRiZWMtOTdiNi1hYWQ4YTZjMjFhMDR9"
```

Đây chính là chuỗi mình cần.

Điều đáng chú ý là comment nói rằng credential được **Base64 encode để tránh secret scanner**.

Nhưng Base64 chỉ là encoding, không phải một cơ chế mã hóa bảo mật. Vì vậy, mình thử giải mã chuỗi này.

---

## 6. Bước 5 – Giải mã Base64

Chuỗi thu được:

```text
ZmxhZ3thN2UzMmE0Mi1hY2NjLTRiZWMtOTdiNi1hYWQ4YTZjMjFhMDR9
```

Có thể sử dụng `base64` trên Linux để decode:

```bash
echo "ZmxhZ3thN2UzMmE0Mi1hY2NjLTRiZWMtOTdiNi1hYWQ4YTZjMjFhMDR9" | base64 -d
```

Kết quả:

```text
flag{a7e32a42-accc-4bec-97b6-aad8a6c21a04}
```

Như vậy, quá trình điều tra đã hoàn tất.

---

## 7. Flag

```text
flag{a7e32a42-accc-4bec-97b6-aad8a6c21a04}
```

---

## 8. Nhìn lại toàn bộ chuỗi OSINT

Điểm quan trọng nhất của challenge này không nằm ở việc decode Base64, mà là **tìm được chuỗi Base64 đó**.

Nếu chỉ nhìn vào challenge ban đầu, thông tin về Nguyễn Minh Khoa khá ít. Nhưng mỗi nguồn công khai lại cung cấp một manh mối dẫn sang nguồn tiếp theo:

```text
┌─────────────────────────────┐
│ arXiv                       │
│ arXiv:2605.99847            │
└──────────────┬──────────────┘
               │
               ↓
┌─────────────────────────────┐
│ X / Twitter                 │
│ @khoa_neuralnet             │
└──────────────┬──────────────┘
               │
               ↓
┌─────────────────────────────┐
│ GitHub                      │
│ minhkhoa-ai                 │
└──────────────┬──────────────┘
               │
               ↓
┌─────────────────────────────┐
│ Repository README           │
│ phantom-gradient-descent    │
└──────────────┬──────────────┘
               │
               ↓
┌─────────────────────────────┐
│ Pastebin                    │
│ r4j92myw                    │
└──────────────┬──────────────┘
               │
               ↓
┌─────────────────────────────┐
│ Base64                      │
│ master_key_b64              │
└──────────────┬──────────────┘
               │
               ↓
        FLAG FOUND
```

Đây chính là đặc trưng của OSINT: **mỗi thông tin riêng lẻ có thể không mang nhiều giá trị, nhưng khi liên kết chúng lại với nhau, chúng tạo thành một chuỗi truy vết hoàn chỉnh**.

---

## 9. Bài học và cách phòng tránh

### 9.1. Cẩn thận với việc liên kết các tài khoản công khai

Việc sử dụng cùng một danh tính trên nhiều nền tảng giúp người khác dễ dàng liên kết các tài khoản với nhau.

Trong challenge này, chỉ từ bài báo trên arXiv có thể tìm được tài khoản X. Từ X lại tìm được GitHub, rồi từ GitHub tìm được Pastebin.

Đối với các dự án nghiên cứu hoặc doanh nghiệp, không nên vô tình tạo ra một chuỗi liên kết từ tài khoản công khai tới tài nguyên nội bộ.

### 9.2. Không lưu credential trên nền tảng công cộng

Pastebin, GitHub Gist hoặc các dịch vụ tương tự không nên được sử dụng để lưu secret, API token hoặc thông tin xác thực.

Đặc biệt, trạng thái **Unlisted** không đồng nghĩa với **Private**.

Nếu người khác có được URL, họ vẫn có thể truy cập nội dung.

### 9.3. Base64 không phải mã hóa

Đây là một lỗi rất dễ gặp.

Base64 chỉ chuyển dữ liệu sang một dạng biểu diễn khác. Bất kỳ ai cũng có thể decode lại mà không cần key.

Ví dụ:

```text
Secret
  ↓
Base64 Encode
  ↓
ZmxhZ3...
```

không có nghĩa là:

```text
Secret
  ↓
Encryption
  ↓
Không thể đọc nếu không có key
```

Do đó, Base64 tuyệt đối không nên được sử dụng để "bảo vệ" credential.

### 9.4. Sử dụng Secret Management

Credential và API token nên được quản lý bằng các cơ chế chuyên dụng thay vì hardcode vào source code hoặc tài liệu.

Một số lựa chọn phổ biến:

* Environment Variables
* HashiCorp Vault
* AWS Secrets Manager
* Azure Key Vault
* Google Cloud Secret Manager

Ngoài ra, nếu một credential đã từng bị public, **không nên chỉ xóa nó khỏi file rồi coi như đã an toàn**. Credential đó cần được revoke hoặc rotate ngay lập tức.

---

## 10. Kết luận

Challenge này là một ví dụ khá điển hình cho việc **digital footprint có thể tiết lộ nhiều thông tin hơn người dùng dự tính**.

Không cần khai thác một lỗ hổng kỹ thuật phức tạp, mình chỉ cần bắt đầu từ một bài nghiên cứu công khai trên arXiv, sau đó lần lượt theo các liên kết mà chính đối tượng để lại trên X, GitHub và Pastebin.

Cuối cùng, một credential được đánh dấu là "internal" lại nằm trên một trang Pastebin công khai và chỉ được Base64 encode. Việc decode chuỗi này giúp lấy được flag.

Điểm mình rút ra từ challenge là: trong OSINT, **đừng chỉ tập trung vào một nguồn thông tin**. Quan trọng hơn là phải biết cách liên kết các dấu vết nhỏ từ nhiều nguồn khác nhau để xây dựng thành một bức tranh hoàn chỉnh.

**Flag:**

```text
flag{a7e32a42-accc-4bec-97b6-aad8a6c21a04}
```
