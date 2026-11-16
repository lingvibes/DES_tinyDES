# DES: khối 64 bit, khóa 64 bit (56 bit hiệu dụng), 16 vòng Feistel
# hàm khối không đệm, hàm byte dùng ECB + PKCS#7
from .bits import (validate_bits, validate_subkeys, to_bit_list, to_bit_str,
                   permute, left_shift, xor_bits)
from .des_tables import (DES_IP, DES_FP, DES_E, DES_P, DES_PC1,
                         DES_PC2, DES_SHIFT, SBOX)

# sinh 16 khóa con

def generate_des_subkeys(K64_str, trace=True):
    # trả về 16 khóa con 48 bit
    validate_bits(K64_str, 64, "Khóa DES")
    # PC-1 bỏ 8 bit parity, còn 56 bit
    K56 = permute(to_bit_list(K64_str), DES_PC1)
    KL, KR = K56[:28], K56[28:]
    log = []
    if trace:
        log += [f"Khóa K = {K64_str}", f"PC-1(K) = {to_bit_str(K56)}",
                f"KL0 = {to_bit_str(KL)}, KR0 = {to_bit_str(KR)}"]
    subkeys = []
    for i, shift in enumerate(DES_SHIFT, start=1):
        # dịch trái hai nửa rồi nén bằng PC-2
        KL, KR = left_shift(KL, shift), left_shift(KR, shift)
        Ki = permute(KL + KR, DES_PC2)
        subkeys.append(Ki)
        if trace:
            log.append(f"Vòng {i}: LS({shift}) -> KL{i}={to_bit_str(KL)}, "
                       f"KR{i}={to_bit_str(KR)} -> K{i}={to_bit_str(Ki)}")
    return subkeys, log

# hàm F

def DES_F_function(R32, Ki48, round_index, log=None):
    # mở rộng E -> xor khóa -> 8 S-box -> hoán vị P
    E = permute(R32, DES_E)
    X = xor_bits(E, Ki48)
    S_out = []
    if log is not None:
        log += [f"  E(R) = {to_bit_str(E)}", f"  E(R) XOR K = {to_bit_str(X)}"]
    for box_index in range(8):
        # mỗi S-box nhận 6 bit: hàng = bit đầu + bit cuối, cột = 4 bit giữa
        six = X[box_index * 6:box_index * 6 + 6]
        row = (six[0] << 1) | six[5]
        col = (six[1] << 3) | (six[2] << 2) | (six[3] << 1) | six[4]
        value = SBOX[box_index][row][col]
        four = to_bit_list(f"{value:04b}")
        S_out.extend(four)
        if log is not None:
            log.append(f"  S{box_index+1}({to_bit_str(six)}): hàng={row}, "
                       f"cột={col} -> {to_bit_str(four)}")
    F_out = permute(S_out, DES_P)
    if log is not None:
        log += [f"  Ghép 8 S-box = {to_bit_str(S_out)}",
                f"  P-box = F{round_index} = {to_bit_str(F_out)}"]
    return F_out

# mã hóa / giải mã 1 khối

def des_process_block(block_str, subkeys, decrypt=False, trace=True):
    validate_bits(block_str, 64, "Khối DES")
    validate_subkeys(subkeys, 16, 48)
    after_IP = permute(to_bit_list(block_str), DES_IP)
    L, R = after_IP[:32], after_IP[32:]
    log = []
    if trace:
        log += [f"Khối vào = {block_str}", f"IP = {to_bit_str(after_IP)}",
                f"L0 = {to_bit_str(L)}, R0 = {to_bit_str(R)}"]
    # giải mã cùng cấu trúc, chỉ đảo thứ tự khóa
    order = range(15, -1, -1) if decrypt else range(16)
    for i, key_index in enumerate(order, start=1):
        Ki = subkeys[key_index]
        if trace:
            log.append(f"\n--- Vòng {i}, dùng K{key_index+1} = {to_bit_str(Ki)} ---")
        F_out = DES_F_function(R, Ki, i, log if trace else None)
        new_L, new_R = R, xor_bits(L, F_out)
        if trace:
            log += [f"  L{i} = R{i-1} = {to_bit_str(new_L)}",
                    f"  R{i} = L{i-1} XOR F{i} = {to_bit_str(new_R)}"]
        L, R = new_L, new_R
    # đổi chỗ hai nửa rồi qua hoán vị cuối
    swapped = R + L
    result = to_bit_str(permute(swapped, DES_FP))
    if trace:
        log += [f"\nR16 || L16 = {to_bit_str(swapped)}", f"IP^-1 -> Kết quả = {result}"]
    return result, log


def DES_encrypt_block(P64_str, subkeys, trace=True):
    return des_process_block(P64_str, subkeys, False, trace)


def DES_decrypt_block(C64_str, subkeys, trace=True):
    return des_process_block(C64_str, subkeys, True, trace)

# văn bản / tệp: ECB + PKCS#7

def des_bytes(data, key_bytes, decrypt=False):
    if len(key_bytes) != 8:
        raise ValueError("Khóa DES phải dài đúng 8 byte.")
    if decrypt:
        if not data or len(data) % 8:
            raise ValueError("Bản mã phải khác rỗng và có độ dài là bội của 8 byte.")
    else:
        # thêm padding cho đủ bội của 8 byte
        padding = 8 - len(data) % 8
        data += bytes([padding]) * padding
    subkeys, _ = generate_des_subkeys(f"{int.from_bytes(key_bytes, 'big'):064b}", False)
    output = bytearray()
    for offset in range(0, len(data), 8):
        block = f"{int.from_bytes(data[offset:offset+8], 'big'):064b}"
        result, _ = des_process_block(block, subkeys, decrypt, False)
        output.extend(int(result, 2).to_bytes(8, 'big'))
    if decrypt:
        # kiểm tra rồi bỏ padding
        padding = output[-1]
        if not 1 <= padding <= 8 or output[-padding:] != bytes([padding]) * padding:
            raise ValueError("Đệm PKCS#7 không hợp lệ: có thể sai khóa hoặc bản mã bị thay đổi.")
        del output[-padding:]
    return bytes(output)
