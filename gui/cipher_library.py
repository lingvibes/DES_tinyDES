# nối giao diện với thuật toán: kiểm tra đầu vào, đối chiếu, vét cạn
import time
from types import SimpleNamespace
from core.tinydes import (generate_subkeys_from_key, tinyDES_encrypt_block,
                          tinyDES_decrypt_block)
from core.des import generate_des_subkeys, des_process_block, des_bytes

try:
    from Crypto.Cipher import DES as StandardDES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    StandardDES = None


def require_standard():
    if StandardDES is None:
        raise ValueError("Chức năng đối chiếu cần PyCryptodome. Chạy: python -m pip install pycryptodome")


# hàm phụ

# bỏ mọi khoảng trắng
def remove_spaces(text):
    return "".join(text.split())

# kiểm tra chuỗi chỉ có ký tự hex
def is_hex(text):
    for character in text:
        if character not in "0123456789ABCDEFabcdef":
            return False
    return True

# số -> hex in hoa đủ digits chữ số, vd number_to_hex(146, 4) = '0092'
def number_to_hex(number, digits):
    text = hex(number)
    text = text[2:].upper()
    while len(text) < digits:
        text = "0" + text
    return text

# số -> nhị phân đủ width bit
def binary(number, width):
    text = bin(number)[2:]
    while len(text) < width:
        text = "0" + text
    return text


# số ms từ lúc start
def milliseconds_since(start):
    return (time.perf_counter() - start) * 1000


# TinyDES

# đọc khối/khóa TinyDES: 8 bit nhị phân hoặc 2 ký tự hex, trả về (số, lỗi)
def read_tinydes_block(text, name):
    text = remove_spaces(text)
    if len(text) == 8 and text.count("0") + text.count("1") == 8:
        return int(text, 2), None
    if len(text) == 2 and is_hex(text):
        return int(text, 16), None
    return None, name + " cần 8 bit nhị phân hoặc 2 ký tự hex."


def tinydes_run(block_text, key_text, decrypt):
    block, error = read_tinydes_block(block_text, "Khối vào")
    if error:
        return None, 0, error
    key, error = read_tinydes_block(key_text, "Khóa")
    if error:
        return None, 0, error
    start = time.perf_counter()
    subkeys, key_log = generate_subkeys_from_key(binary(key, 8))
    process = tinyDES_decrypt_block if decrypt else tinyDES_encrypt_block
    output, log = process(binary(block, 8), subkeys)
    elapsed = milliseconds_since(start)
    return SimpleNamespace(out=int(output, 2), log=key_log + log), elapsed, None


def tinydes_steps(trace, decrypt):
    return "\n".join(trace.log)


# thử 256 khóa, giữ khóa nào mã hóa P ra đúng C
def tinydes_bruteforce(plaintext_text, ciphertext_text):
    plaintext, error = read_tinydes_block(plaintext_text, "Bản rõ")
    if error:
        return None, error
    ciphertext, error = read_tinydes_block(ciphertext_text, "Bản mã")
    if error:
        return None, error

    found_keys = []
    for key in range(256):
        if tinyDES_encrypt_block(binary(plaintext, 8),
                                 generate_subkeys_from_key(binary(key, 8))[0])[0] == binary(ciphertext, 8):
            found_keys.append(number_to_hex(key, 2))
    return found_keys, None


# DES: văn bản, tệp
# đọc khóa thành 8 byte: "hex" = 16 ký tự hex, "text" = 8 byte UTF-8
def read_des_key(key_text, key_type):
    if key_type == "hex":
        key_hex = remove_spaces(key_text)
        if len(key_hex) != 16 or not is_hex(key_hex):
            return None, "Khóa hex cần đúng 16 ký tự 0-9, A-F."
        return bytes.fromhex(key_hex), None

    key_bytes = key_text.encode("utf-8")
    if len(key_bytes) != 8:
        return None, ("Khóa chữ cần đúng 8 byte (hiện có " + str(len(key_bytes)) + " byte). "
                      "Chữ có dấu tiếng Việt chiếm 2-3 byte mỗi ký tự.")
    return key_bytes, None


# DES của nhóm
def group_des(data, key_bytes, decrypt):
    try:
        return des_bytes(data, key_bytes, bool(decrypt))
    except ValueError:
        return None


# DES của PyCryptodome (ECB + PKCS#7), dùng để đối chiếu
def standard_des(data, key_bytes, decrypt):
    require_standard()
    standard_cipher = StandardDES.new(key_bytes, StandardDES.MODE_ECB)
    if decrypt == 0:
        return standard_cipher.encrypt(pad(data, 8))

    decrypted = standard_cipher.decrypt(data)
    try:
        return unpad(decrypted, 8)
    except ValueError:
        return None


# mã hóa/giải mã dữ liệu dài, khi giải mã data là chuỗi hex
def des_text(data, key_bytes, decrypt, use_standard):
    if decrypt and len(data) == 0:
        return None, "Chưa có dữ liệu: hãy gõ văn bản hoặc chọn tệp .txt."

    # giải mã: đổi chuỗi hex thành byte
    if decrypt == 1:
        try:
            hex_text = data.decode("ascii")
        except UnicodeDecodeError:
            return None, "Bản mã phải là chuỗi hex ASCII."
        hex_text = "".join(hex_text.split())
        if not hex_text or len(hex_text) % 16 != 0 or not is_hex(hex_text):
            return None, "Bản mã phải là chuỗi hex (0-9, A-F), độ dài là bội của 16."
        data = bytes.fromhex(hex_text)

    start = time.perf_counter()
    if use_standard:
        output = standard_des(data, key_bytes, decrypt)
    else:
        output = group_des(data, key_bytes, decrypt)
    milliseconds = milliseconds_since(start)

    if output is None:
        return None, "Giải mã thất bại: sai khóa hoặc bản mã không hợp lệ."

    result = {"milliseconds": milliseconds, "raw_output": output}
    if decrypt == 0:
        result["output"] = output.hex().upper()
        result["blocks"] = len(output) // 8
    else:
        result["output"] = output.decode("utf-8", errors="replace")
        result["blocks"] = len(data) // 8
    return result, None


# kiểm thử 1 khối

# mã hóa 1 khối 64 bit bằng PyCryptodome (không đệm)
def standard_one_block(plaintext_text, key_text):
    plaintext_hex = remove_spaces(plaintext_text)
    key_hex = remove_spaces(key_text)
    if len(plaintext_hex) != 16 or len(key_hex) != 16 or not is_hex(plaintext_hex + key_hex):
        return None, "Bản rõ và khóa cần đúng 16 ký tự hex (0-9, A-F)."

    require_standard()
    standard_cipher = StandardDES.new(bytes.fromhex(key_hex), StandardDES.MODE_ECB)
    ciphertext = standard_cipher.encrypt(bytes.fromhex(plaintext_hex))
    return ciphertext.hex().upper(), None


# mã hóa (decrypt = 0) hoặc giải mã (decrypt = 1) 1 khối 64 bit bằng DES của nhóm
def group_one_block(block_text, key_text, decrypt):
    block_hex = remove_spaces(block_text)
    key_hex = remove_spaces(key_text)
    if len(block_hex) != 16 or len(key_hex) != 16 or not is_hex(block_hex + key_hex):
        return None, "Khối vào và khóa cần đúng 16 ký tự hex (0-9, A-F)."

    block = int(block_hex, 16)
    key = int(key_hex, 16)
    subkeys, _ = generate_des_subkeys(binary(key, 64), False)
    output_bits, _ = des_process_block(binary(block, 64), subkeys, bool(decrypt), False)
    output = int(output_bits, 2)
    return number_to_hex(output, 16), None


# vét cạn DES rút gọn

# viết khóa 64 bit theo từng byte, thay unknown_bits bit hiệu dụng cuối bằng '?'
# bit cuối mỗi byte là bit parity nên bỏ qua
def key_with_unknown_bits(key, unknown_bits):
    bits = list(bin(key)[2:].zfill(64))

    # đi từ bit phải nhất sang trái
    position = 63
    remaining = unknown_bits
    while remaining > 0:
        if position % 8 != 7:
            bits[position] = "?"
            remaining = remaining - 1
        position = position - 1

    text = ""
    for i in range(0, 64, 8):
        text += "".join(bits[i:i + 8]) + " "
    return text.strip()


# log sinh khóa và 16 vòng của 1 khối
def des_block_steps(block_text, key_text, decrypt):
    result, error = group_one_block(block_text, key_text, decrypt)
    if error:
        raise ValueError(error)
    key = int(remove_spaces(key_text), 16)
    block = int(remove_spaces(block_text), 16)
    subkeys, key_log = generate_des_subkeys(binary(key, 64))
    _, log = des_process_block(binary(block, 64), subkeys, bool(decrypt))
    return "\n".join(key_log + log)


# giả sử đã biết hết khóa trừ N bit hiệu dụng cuối, thử hết 2^N khóa
def des_bruteforce(plaintext_text, key_text, unknown_bits, cancel=None):
    ciphertext_hex, error = group_one_block(plaintext_text, key_text, 0)
    if error:
        return None, error
    if not 8 <= unknown_bits <= 20:
        return None, "Số bit chưa biết N phải từ 8 đến 20."
    plaintext = binary(int(remove_spaces(plaintext_text), 16), 64)
    key = int(remove_spaces(key_text), 16)
    ciphertext = binary(int(ciphertext_hex, 16), 64)
    # vị trí N bit chưa biết, bỏ bit parity
    positions = [p for p in range(64) if p % 8 != 0][:unknown_bits]
    base_key = key
    for position in positions:
        base_key &= ~(1 << position)
    found_count, found_key, found_index = 0, 0, 0
    start = time.perf_counter()
    total = 2 ** unknown_bits
    tried = 0
    for guess in range(total):
        if cancel is not None and cancel.is_set():
            break
        # ghép lần đoán vào các vị trí chưa biết
        candidate = base_key
        for i, position in enumerate(positions):
            if (guess >> i) & 1:
                candidate |= 1 << position
        subkeys, _ = generate_des_subkeys(binary(candidate, 64), False)
        output, _ = des_process_block(plaintext, subkeys, False, False)
        tried += 1
        if output == ciphertext:
            if found_count == 0:
                found_key, found_index = candidate, tried
            found_count += 1
    seconds = max(time.perf_counter() - start, 1e-9)
    speed = tried / seconds
    # ước tính thời gian thử hết 2^56 khóa theo tốc độ vừa đo
    full_years = (2 ** 56) / max(speed, 1e-9) / (365 * 24 * 3600)
    return {
        "plaintext": remove_spaces(plaintext_text).upper(),
        "ciphertext": ciphertext_hex,
        "known_key": key_with_unknown_bits(key, unknown_bits),
        "unknown_bits": unknown_bits, "tried": tried,
        "found_count": found_count,
        "found_key": number_to_hex(found_key, 16) if found_count else "Chưa tìm thấy",
        "found_index": found_index,
        "seconds": round(seconds, 3), "speed": int(speed),
        "full_years": int(full_years), "average_years": int(full_years / 2),
        "cancelled": tried < total,
    }, None
