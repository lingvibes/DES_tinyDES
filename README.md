# Hệ mã khối DES và TinyDES

Bài tập nhóm môn **An toàn và bảo mật thông tin**. Chương trình minh họa mã hóa, giải mã, sinh khóa con và các bước của mạng Feistel bằng Python, với giao diện Tkinter.

Code chính nằm ở hai thư mục: **`core/`** chứa thuật toán và **`gui/`** chứa giao diện, kiểm tra đầu vào, đối chiếu và mô phỏng vét cạn.

## Cấu trúc thư mục

```text
DES_tinyDES/
  core/
    __init__.py          Khai báo gói thuật toán
    bits.py              Kiểm tra dữ liệu, hoán vị, XOR và dịch vòng bit
    tinydes.py           TinyDES: sinh 3 khóa con, hàm F, mã hóa và giải mã
    des_tables.py        Các bảng IP, FP, E, P, PC-1, PC-2, lịch dịch và S-box
    des.py               DES: sinh 16 khóa con, xử lý khối, ECB và đệm PKCS#7
  gui/
    __init__.py          Khai báo gói giao diện
    app.py               Giao diện Tkinter gồm 4 tab
    cipher_library.py    Nối giao diện với thuật toán, đối chiếu và vét cạn
  app.py                 Điểm khởi động chương trình
  Chay_chuong_trinh.bat   Chạy nhanh trên Windows
  requirements.txt       Thư viện dùng để đối chiếu kết quả
  test_algorithms.py     Bộ kiểm thử thuật toán
  README.md              Hướng dẫn dự án
```

Tên thư mục sau khi tải ZIP từ GitHub có thể là `DES_tinyDES-main`. Các thư mục `__pycache__/` là bộ nhớ đệm do Python tự tạo, không phải mã nguồn cần đọc hoặc đưa lên Git.

## Bắt đầu đọc code

- **Khởi động:** mở [`app.py`](app.py); tệp này gọi `main()` trong [`gui/app.py`](gui/app.py).
- **Giao diện:** đọc [`gui/app.py`](gui/app.py), bắt đầu từ `main()` và các hàm `build_*_tab()` để xem cách tạo bốn tab và nối các nút xử lý.
- **Xử lý đầu vào:** đọc [`gui/cipher_library.py`](gui/cipher_library.py); các hàm chuyển dữ liệu nhị phân/hex, đọc khóa, đo thời gian và gọi thuật toán nằm tại đây.
- **TinyDES:** đọc [`core/tinydes.py`](core/tinydes.py) theo thứ tự sinh khóa con → hàm F → mã hóa → giải mã.
- **DES:** đọc [`core/des.py`](core/des.py); tra bảng trong [`core/des_tables.py`](core/des_tables.py) và các hàm bit dùng chung trong [`core/bits.py`](core/bits.py).
- **Vét cạn và đối chiếu:** đọc `tinydes_bruteforce()`, `des_bruteforce()` và các hàm `standard_*()` trong `gui/cipher_library.py`.

## Yêu cầu

- Python 3.10 trở lên, có Tkinter và môi trường hiển thị cửa sổ đồ họa.
- PyCryptodome để dùng tab **Kiểm thử** và các phép đối chiếu độc lập trong bộ kiểm thử.

Thuật toán chính được viết bằng Python, không cần biên dịch C hoặc nạp DLL. Khi chưa cài PyCryptodome, các chức năng mã hóa, giải mã và vét cạn bằng thuật toán của nhóm vẫn sử dụng được.

## Chạy chương trình

Giải nén dự án, mở Terminal tại thư mục chứa tệp `app.py` ngoài cùng.

Cài thư viện đối chiếu:

```sh
python -m pip install -r requirements.txt
```

Mở giao diện:

```sh
python app.py
```

Trên Windows, có thể nháy đúp `Chay_chuong_trinh.bat`. Nếu máy sử dụng lệnh `py`, chạy `py app.py`.

Giữ nguyên vị trí của hai thư mục `core/`, `gui/` cạnh tệp `app.py` ngoài cùng. Không chạy trực tiếp `gui/app.py`. Đây là ứng dụng cửa sổ Tkinter, không phải website; hãy chạy trên máy có môi trường đồ họa để sử dụng giao diện.

## Chức năng

| Tab | Chức năng |
|---|---|
| **TinyDES** | Mã hóa/giải mã khối 8 bit với khóa 8 bit, qua 3 vòng Feistel. Hiển thị khóa con, Expand, XOR, S-box, P-box và thời gian xử lý. |
| **DES** | Mã hóa/giải mã một khối 64 bit không đệm, mở log sinh khóa và 16 vòng; xử lý văn bản hoặc tệp bằng ECB + PKCS#7. |
| **Kiểm thử** | So sánh kết quả mã hóa một khối với PyCryptodome; mã hóa/giải mã văn bản hoặc tệp bằng thư viện chuẩn để đối chiếu với tab DES. |
| **Tấn công vét cạn** | Thử 256 khóa TinyDES; mô phỏng tìm 8–20 bit khóa DES còn thiếu khi đã biết các bit khác. Hiển thị số khóa đã thử, thời gian, tốc độ và ước tính cho không gian khóa đầy đủ. Có nút hủy vét cạn DES. |

### Dữ liệu đầu vào

| Chế độ | Dữ liệu | Khóa |
|---|---|---|
| TinyDES | 8 ký tự nhị phân hoặc 2 ký tự hex | 8 ký tự nhị phân hoặc 2 ký tự hex |
| DES một khối | 16 ký tự hex | 16 ký tự hex |
| DES văn bản/tệp — mã hóa | Văn bản UTF-8 hoặc dữ liệu từ tệp | 16 ký tự hex hoặc chuỗi dài đúng 8 byte UTF-8 |
| DES văn bản/tệp — giải mã | Bản mã hex, độ dài sau khi bỏ khoảng trắng là bội của 16 | Cùng khóa đã dùng để mã hóa |

Khóa chữ tính theo **byte**, không phải số ký tự: `12345678` là 8 byte; chữ có dấu có thể chiếm nhiều byte.

### Mã hóa và giải mã văn bản/tệp

1. Chọn kiểu khóa và nhập khóa trong tab **DES**.
2. Nhập văn bản hoặc bấm **Chọn tệp...**, sau đó bấm **Mã hóa**.
3. Bấm **Dùng kết quả làm đầu vào**, giữ nguyên khóa rồi bấm **Giải mã** để phục hồi dữ liệu.
4. Bấm **Lưu kết quả...** để lưu kết quả của lần xử lý thành công gần nhất.

Nếu đã chọn tệp, chương trình ưu tiên tệp đó. Bấm **Bỏ tệp** để dùng ô nhập; nút **Dùng kết quả làm đầu vào** cũng bỏ lựa chọn tệp cũ. Bản mã được lưu dưới dạng hex; kết quả giải mã được lưu bằng byte gốc. Ô hiển thị đọc theo UTF-8 nên dữ liệu nhị phân có thể không hiển thị thành chữ.

## Đặc điểm thuật toán

**TinyDES:** chia khối thành hai nửa 4 bit, sinh ba khóa con 6 bit với lịch dịch `[1, 2, 1]`. Hàm F thực hiện Expand → XOR khóa con → S-box → P-box. Bản mã là `L3 || R3`, không đổi chỗ cuối; giải mã đi ngược từng vòng với K3, K2, K1.

Các bảng TinyDES trong phiên bản này, với chỉ số tính từ 0 ở bit trái nhất:

| Thành phần | Thứ tự bit |
|---|---|
| Expand 4 → 6 | `[2, 3, 1, 2, 3, 0]` |
| Compress khóa 8 → 6 | `[5, 2, 6, 3, 1, 0]` |
| P-box 4 → 4 | `[2, 0, 3, 1]` |

**DES:** khóa đầu vào 64 bit, PC-1 bỏ 8 bit parity còn 56 bit hiệu dụng. Thuật toán thực hiện IP → 16 vòng Feistel → ghép `R16 || L16` → FP. Giải mã dùng cùng cấu trúc và đảo thứ tự khóa con. Chế độ một khối không đệm; chế độ văn bản/tệp sử dụng ECB và PKCS#7.

## Ví dụ chạy thử

| Thuật toán | Bản rõ (hex) | Khóa (hex) | Bản mã (hex) |
|---|---|---|---|
| TinyDES | `5C` | `9E` | `E1` |
| DES một khối, không đệm | `0123456789ABCDEF` | `133457799BBCDFF1` | `85E813540F0AB405` |

Với TinyDES, các giá trị tương ứng ở dạng nhị phân là bản rõ `01011100`, khóa `10011110` và bản mã `11100001`.

## Kiểm thử

Tại thư mục gốc dự án, chạy:

```sh
python -m unittest -v test_algorithms.py
```

Bộ kiểm thử bao gồm:

- Vector mẫu DES và giải mã ngược.
- Toàn bộ 65.536 cặp khóa/khối TinyDES, kiểm tra phục hồi bản rõ và tính hoán vị.
- 100 khối DES ngẫu nhiên đối chiếu với PyCryptodome.
- Dữ liệu rỗng, ranh giới khối, tiếng Việt, dữ liệu nhị phân và đệm sai.
- Kiểm tra đầu vào và quy trình mã hóa/giải mã văn bản.
- Vét cạn DES với 8 bit chưa biết và hủy tác vụ.

Nếu chưa cài PyCryptodome, phép kiểm thử đối chiếu độc lập sẽ được bỏ qua (`skipped`). Bộ kiểm thử này kiểm tra thuật toán, không tự kiểm tra thao tác trên cửa sổ giao diện.

## Lưu ý

Vét cạn DES chạy bằng Python; nên bắt đầu với N = 8 vì số khả năng tăng theo `2^N`. Ước tính thời gian chỉ dựa trên tốc độ bản triển khai này trên máy đang chạy. Một cặp bản rõ/bản mã TinyDES có thể cho nhiều khóa phù hợp.

Dự án phục vụ học tập và minh họa thuật toán. DES, TinyDES và chế độ ECB trong chương trình không dành cho bảo vệ dữ liệu thực tế; kiểm tra đệm PKCS#7 không thay thế kiểm tra tính toàn vẹn.
