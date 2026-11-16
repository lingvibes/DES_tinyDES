# hàm dùng chung cho DES: kiểm tra, hoán vị, xor, dịch vòng


def validate_bits(text, width, name="Dữ liệu"):
    # chuỗi phải đúng width ký tự 0/1
    if len(text) != width or any(bit not in "01" for bit in text):
        raise ValueError(f"{name} phải gồm đúng {width} bit 0/1.")


def validate_subkeys(subkeys, count, width):
    # đủ count khóa con, mỗi khóa width bit
    if len(subkeys) != count or any(
        len(key) != width or any(bit not in (0, 1) for bit in key)
        for key in subkeys
    ):
        raise ValueError(f"Cần {count} khóa con, mỗi khóa gồm {width} bit.")


def to_bit_list(text):
    return [int(bit) for bit in text]


def to_bit_str(bits):
    return "".join(str(bit) for bit in bits)


def permute(bits, table):
    # lấy bit theo bảng, chỉ số từ 0
    return [bits[position] for position in table]


def left_shift(bits, n=1):
    # dịch vòng trái n bit
    n %= len(bits)
    return bits[n:] + bits[:n]


def xor_bits(a, b):
    if len(a) != len(b):
        raise ValueError("Hai dãy bit XOR phải cùng độ dài.")
    return [x ^ y for x, y in zip(a, b)]
