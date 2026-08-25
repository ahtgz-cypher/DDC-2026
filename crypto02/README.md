# DDC CTF — Crypto Challenge 2: Recovering a Small LWE Secret with Lattice Reduction

> **Category:** Cryptography / LWE / Lattice
> **Difficulty:** Hard
> **Status:** Solved
> **Vulnerability:** Weak LWE Parameters / Small Secret / Recoverable Secret via Lattice Reduction
> **Objective:** Recover the secret key and decrypt the encrypted flag

---

# 1. Challenge Overview

Challenge sử dụng một biến thể của **Learning With Errors (LWE)**.

Server sinh ra một secret vector có giá trị rất nhỏ:

```text
N = 50
Q = 10007
secret[i] ∈ [-3, 3]
noise ∈ {-1, 0, 1}
```

Với mỗi sample, server tạo:

```text
b = <A, secret> + noise mod Q
```

trong đó:

* `A` là vector ngẫu nhiên có 50 phần tử.
* `secret` là vector bí mật.
* `noise` chỉ có giá trị `-1`, `0`, `1`.
* `Q = 10007` là modulus.

Mục tiêu là:

1. Thu thập các LWE samples.
2. Khôi phục secret vector.
3. Sử dụng secret để giải mã ciphertext của flag.

---

# 2. Understanding the LWE Construction

Một sample có dạng:

```text
b = <A, s> + e mod Q
```

hay viết chi tiết:

```text
b = A₁s₁ + A₂s₂ + ... + A₅₀s₅₀ + e mod Q
```

Trong đó:

```text
A = public vector
s = secret vector
e = small error/noise
```

Thông thường, bài toán LWE dựa trên việc khiến việc tìm `s` từ nhiều phương trình như trên trở nên khó.

Nhưng challenge này sử dụng các tham số rất yếu.

Secret chỉ có:

```text
sᵢ ∈ [-3, 3]
```

và noise chỉ có:

```text
e ∈ {-1, 0, 1}
```

Điều này tạo ra một vector nghiệm cực kỳ nhỏ.

Đây chính là điểm yếu mà lattice attack có thể khai thác.

---

# 3. The Encryption Scheme

Ngoài các LWE samples thông thường, server còn cung cấp chức năng `encrypt` để mã hóa từng bit của flag.

Với một bit `m`, server trước tiên tính:

```text
b = <A, secret> + noise
```

Sau đó nếu bit bằng `1`, server cộng thêm:

```text
Q // 2
```

Tức là:

```text
bit = 0

b ≈ <A, secret>
```

trong khi:

```text
bit = 1

b ≈ <A, secret> + Q/2
```

Sau khi lấy modulo `Q`, hai trường hợp này tạo ra hai vùng giá trị khác nhau.

Có thể hình dung:

```text
                 Q/2
                  │
                  ▼

bit 0        bit 1
  │             │
  ▼             ▼

[noise]      [Q/2 + noise]
  -1 0 1      Q/2-1 Q/2 Q/2+1
```

Do đó, chỉ cần khôi phục `secret`, việc giải mã flag trở nên rất đơn giản.

---

# 4. Collecting LWE Samples

Ta thu thập khoảng 60 samples:

```text
(A₁, b₁)
(A₂, b₂)
...
(A₆₀, b₆₀)
```

Mỗi sample thỏa mãn:

```text
bᵢ = <Aᵢ, s> + eᵢ mod Q
```

Ta có:

```text
m = 60
n = 50
```

với:

* `m`: số lượng samples.
* `n`: số chiều của secret.

Vấn đề cần giải quyết là tìm:

```text
s ∈ [-3, 3]^50
```

và các error:

```text
eᵢ ∈ {-1, 0, 1}
```

---

# 5. Why Brute Force Is Impossible

Secret có 50 phần tử và mỗi phần tử có 7 khả năng:

```text
sᵢ ∈ {-3,-2,-1,0,1,2,3}
```

Số secret có thể có là:

```text
7^50
```

Đây là một không gian tìm kiếm khổng lồ.

Do đó không thể brute-force secret trực tiếp.

Thay vào đó, ta tận dụng cấu trúc toán học của bài toán.

---

# 6. Turning LWE into a Lattice Problem

Từ phương trình:

```text
bᵢ = <Aᵢ, s> + eᵢ mod Q
```

ta có thể viết:

```text
<Aᵢ, s> - bᵢ + eᵢ = kᵢQ
```

với một số nguyên `kᵢ`.

Điểm quan trọng là:

```text
sᵢ rất nhỏ
eᵢ rất nhỏ
```

Trong khi:

```text
Q = 10007
```

là tương đối lớn.

Ta có thể xây dựng một lattice sao cho vector chứa:

```text
(e₁, ..., eₘ, s₁, ..., sₙ, 1)
```

hoặc dấu của `s` tùy cách xây dựng basis, trở thành một vector có norm rất nhỏ.

Đây là ý tưởng cốt lõi của **Kannan embedding**.

---

# 7. Kannan Embedding

Với:

```text
m = 60
n = 50
```

ta xây dựng basis có kích thước:

```text
(m + n + 1) × (m + n + 1)
```

tức:

```text
111 × 111
```

Một dạng basis sử dụng trong challenge là:

```text
[ QI_m       0       0 ]
[ A^T        I_n     0 ]
[ b          0       1 ]
```

Trong đó:

* `I_m` là ma trận đơn vị kích thước `m`.
* `I_n` là ma trận đơn vị kích thước `n`.
* `A` là ma trận chứa các public vectors.
* `b` là vector các ciphertext/sample values.
* `Q` là modulus.

Mục tiêu của embedding là biến bài toán tìm nghiệm LWE thành bài toán tìm một vector ngắn trong lattice.

---

# 8. Why the Secret Becomes a Short Vector

Từ hệ phương trình:

```text
bᵢ = <Aᵢ, s> + eᵢ mod Q
```

ta có:

```text
<Aᵢ, s> + eᵢ - bᵢ = kᵢQ
```

Do đó:

```text
Aᵢ · s + eᵢ - bᵢ
```

là một bội của `Q`.

Khi đưa các phương trình này vào lattice, một combination của các basis vectors có thể tạo ra vector chứa:

```text
(e₁, e₂, ..., e₆₀,
 s₁, s₂, ..., s₅₀,
 1)
```

Về độ lớn:

```text
eᵢ ∈ {-1,0,1}
```

và:

```text
sᵢ ∈ [-3,3]
```

nên vector này rất ngắn.

Trong khi các vector ngẫu nhiên khác của lattice thường có norm lớn hơn nhiều.

Đây là điểm cho phép **LLL** tìm ra nghiệm.

---

# 9. LLL Reduction

**LLL (Lenstra–Lenstra–Lovász)** là thuật toán dùng để giảm một lattice basis về một basis "ngắn" và "gần trực giao" hơn.

Nó không trực tiếp giải LWE.

Thay vào đó:

```text
LWE equations
      │
      ▼
Lattice construction
      │
      ▼
Kannan embedding
      │
      ▼
LLL reduction
      │
      ▼
Short vector
      │
      ▼
Recover secret
```

Trong challenge, chạy LLL hai giai đoạn:

```text
delta = 0.75
```

sau đó tiếp tục với:

```text
delta = 0.95
```

giúp thu được vector nghiệm mong muốn.

---

# 10. Recovered Secret

Sau khi thực hiện lattice reduction, ta khôi phục được secret:

```text
[
  2, -2, -2, 1, -1, 1, 1, -1, 2, -3,
 -1,  1, -3, 0,  2, -2, -2, 3, 0, 2,
 -2,  3,  3, 2,  0, -2, -3, -1, 1, 0,
  3,  0,  1,-3,  1,  3, 0, 3, 0,-1,
 -1,  1,  2,-1,  3, -1, 2, 2,-3, 1
]
```

Kiểm tra:

```text
len(secret) = 50
```

và tất cả phần tử đều nằm trong:

```text
[-3, 3]
```

phù hợp với parameter ban đầu của challenge.

Đây là một dấu hiệu mạnh cho thấy vector thu được chính là secret.

---

# 11. Decrypting the Ciphertext

Sau khi có secret, ta không cần thực hiện lattice attack nữa.

Với mỗi encrypted sample `(A, b)`, tính:

```text
v = (b - dot(A, secret)) % Q
```

Nếu plaintext bit là `0`, ta có:

```text
v = noise mod Q
```

Do:

```text
noise ∈ {-1,0,1}
```

nên:

```text
v ∈ {Q-1, 0, 1}
```

Với:

```text
Q = 10007
```

ta có:

```text
v ∈ {10006, 0, 1}
```

---

Nếu plaintext bit là `1`, server đã cộng thêm:

```text
Q // 2
```

Do đó:

```text
v = Q//2 + noise
```

và:

```text
v ∈ {Q//2 - 1, Q//2, Q//2 + 1}
```

Với:

```text
Q // 2 = 5003
```

ta có:

```text
v ∈ {5002, 5003, 5004}
```

Vì vậy việc xác định bit rất đơn giản:

```text
{10006, 0, 1}       → bit 0

{5002, 5003, 5004}  → bit 1
```

---

# 12. Reconstructing Bytes

Các bit được server mã hóa theo thứ tự little-endian trong từng byte.

Do đó với 8 bit:

```text
bit[0]
bit[1]
...
bit[7]
```

ta reconstruct byte bằng:

```python
value = sum(bit[i] << i for i in range(8))
```

Ví dụ nếu:

```text
bits = [1, 0, 0, 0, 0, 1, 1, 0]
```

thì:

```text
value =
1 << 0
+ 0 << 1
+ 0 << 2
+ 0 << 3
+ 0 << 4
+ 1 << 5
+ 1 << 6
+ 0 << 7

= 97
```

và:

```text
97 = ord('a')
```

Lặp lại quá trình cho toàn bộ ciphertext sẽ reconstruct được flag.

---

# 13. Decryption Logic

Logic giải mã có thể mô tả ngắn gọn:

```python
v = (b - dot(A, secret)) % Q

if v in {Q - 1, 0, 1}:
    bit = 0

elif v in {Q // 2 - 1, Q // 2, Q // 2 + 1}:
    bit = 1

else:
    raise ValueError("Invalid ciphertext")
```

Sau đó group mỗi 8 bit:

```python
value = sum(bit[i] << i for i in range(8))
```

và convert thành ASCII.

---

# 14. Why the Attack Works

Điểm yếu chính không nằm ở bản thân ý tưởng LWE.

LWE có thể được sử dụng để xây dựng các cryptosystem mạnh khi tham số được chọn đúng.

Vấn đề ở challenge là secret quá nhỏ:

```text
secret[i] ∈ [-3, 3]
```

và noise cũng cực kỳ nhỏ:

```text
noise ∈ {-1, 0, 1}
```

Trong khi attacker có thể thu thập nhiều samples:

```text
bᵢ = <Aᵢ, s> + eᵢ mod Q
```

Kết quả là nghiệm:

```text
(e₁, ..., eₘ, s₁, ..., sₙ, 1)
```

trở thành một vector rất ngắn trong lattice.

LLL có thể khai thác cấu trúc này để đưa vector đó ra khỏi không gian tìm kiếm khổng lồ.

---

# 15. Attack Flow

Toàn bộ quá trình:

```text
              LWE Samples
                   │
                   ▼
        b = <A, secret> + noise
                   │
                   ▼
          Collect ~60 samples
                   │
                   ▼
          Build Lattice Basis
                   │
                   ▼
         Kannan Embedding
                   │
                   ▼
             LLL Reduction
                   │
                   ▼
          Recover Short Vector
                   │
                   ▼
            Recover Secret
                   │
                   ▼
       Compute b - <A, secret>
                   │
          ┌────────┴────────┐
          ▼                 ▼
       near 0            near Q/2
          │                 │
          ▼                 ▼
        bit = 0           bit = 1
          │                 │
          └────────┬────────┘
                   ▼
             Group 8 bits
                   │
                   ▼
               ASCII
                   │
                   ▼
flag{bc3bfb6e-2c6f-4393-92e9-1819b6c61991}
```

---

# 16. Root Cause

Root cause của challenge là việc sử dụng một biến thể LWE với secret quá nhỏ và cho phép attacker thu thập nhiều samples.

Các parameter đáng chú ý:

```text
N = 50
Q = 10007
secret[i] ∈ [-3, 3]
noise ∈ {-1, 0, 1]
```

Đặc biệt:

```text
secret[i] ∈ [-3, 3]
```

làm secret có entropy rất thấp so với một LWE secret thông thường.

Khi kết hợp với:

```text
~60 samples
```

ta có đủ nhiều phương trình để xây dựng lattice và tìm nghiệm ngắn.

---

# 17. Lessons Learned

Challenge này minh họa một nguyên tắc quan trọng trong cryptography:

> **Không thể biến một cryptosystem an toàn thành một cryptosystem an toàn chỉ bằng cách giữ nguyên công thức nhưng chọn parameter yếu.**

LWE dựa vào hardness của một bài toán lattice.

Nhưng nếu:

```text
Secret quá nhỏ
+
Noise quá nhỏ
+
Có quá nhiều samples
```

thì cấu trúc của secret có thể bị khai thác bằng lattice reduction.

Attack chain ở đây là:

```text
Weak Parameters
      ↓
Small Secret
      ↓
Small Error
      ↓
Short Vector
      ↓
Lattice Embedding
      ↓
LLL
      ↓
Secret Recovery
      ↓
Decrypt Flag
```

---

# 18. Final Flag

```text
flag{bc3bfb6e-2c6f-4393-92e9-1819b6c61991}
```

---

## 19. TL;DR

Server sử dụng:

```text
b = <A, secret> + noise mod Q
```

với:

```text
secret[i] ∈ [-3,3]
noise ∈ {-1,0,1}
```

Thu thập khoảng 60 samples và xây dựng lattice bằng **Kannan embedding**.

Sau đó dùng **LLL reduction** để tìm vector ngắn chứa secret.

Recovered secret:

```text
[2, -2, -2, 1, -1, 1, 1, -1, 2, -3,
 -1, 1, -3, 0, 2, -2, -2, 3, 0, 2,
 -2, 3, 3, 2, 0, -2, -3, -1, 1, 0,
  3, 0, 1, -3, 1, 3, 0, 3, 0, -1,
 -1, 1, 2, -1, 3, -1, 2, 2, -3, 1]
```

Sau đó với mỗi ciphertext:

```text
v = (b - <A, secret>) mod Q
```

Phân biệt:

```text
v ≈ 0       → bit 0
v ≈ Q/2     → bit 1
```

Ghép 8 bit theo little-endian để lấy ASCII.

Kết quả:

```text
flag{bc3bfb6e-2c6f-4393-92e9-1819b6c61991}
```
