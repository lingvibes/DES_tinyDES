# TinyDES: khối 8 bit, khóa 8 bit, 3 vòng Feistel
from .bits import validate_bits, validate_subkeys

# hàm xử lý bit

def to_bit_list(bit_str):
    if not bit_str or any(b not in "01" for b in bit_str):
        raise ValueError("Dãy bit chỉ được chứa 0 và 1.")
    return [int(b) for b in bit_str]

def to_bit_str(bit_list):
    return "".join(str(b) for b in bit_list)

def left_shift(bits, n=1):
    n = n % len(bits)
    return bits[n:] + bits[:n]

def xor_bits(a, b):
    if len(a) != len(b):
        raise ValueError("Hai dãy bit XOR phải cùng độ dài.")
    return [x ^ y for x, y in zip(a, b)]

# Expand, S-box, P-box

def expand_4_to_6(R4):
    # mở rộng 4 -> 6 bit: b2 b3 b1 b2 b1 b0
    b0, b1, b2, b3 = R4
    return [b2, b3, b1, b2, b1, b0]

# S-box 4 hàng x 16 cột (lấy S1 của DES)
SBOX = [
    [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
    [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
    [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
    [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
]

def sbox_6_to_4(X6):
    # hàng = b0 b5, cột = b1 b2 b3 b4
    b0,b1,b2,b3,b4,b5 = X6
    row = (b0 << 1) | b5
    col = (b1 << 3) | (b2 << 2) | (b3 << 1) | b4
    val = SBOX[row][col]
    return [
        (val >> 3) & 1,
        (val >> 2) & 1,
        (val >> 1) & 1,
        val & 1
    ]

def pbox_4(bits4):
    # hoán vị 4 bit: b2 b0 b3 b1
    b0,b1,b2,b3 = bits4
    return [b2, b0, b3, b1]

# sinh khóa con

def compress_8_to_6(K8):
    # nén 8 -> 6 bit: k5 k2 k6 k3 k1 k0 (bỏ k4, k7)
    k0,k1,k2,k3,k4,k5,k6,k7 = K8
    return [k5, k2, k6, k3, k1, k0]

def generate_subkeys_from_key(K8_str):
    # tách khóa thành KL, KR; dịch trái 1, 2, 1 bit rồi nén ra K1, K2, K3
    log = []
    validate_bits(K8_str, 8, "Khóa TinyDES")
    K8 = to_bit_list(K8_str)
    log.append(f"Khóa chính K  = {to_bit_str(K8)}")

    KL = K8[:4]
    KR = K8[4:]
    log.append(f"Chia khóa: KL0 = {to_bit_str(KL)}, KR0 = {to_bit_str(KR)}")

    subkeys = []
    # số bit dịch của 3 vòng
    shifts = [1, 2, 1]

    for round_idx, sh in enumerate(shifts, start=1):
        KL = left_shift(KL, sh)
        KR = left_shift(KR, sh)
        Ki = compress_8_to_6(KL + KR)
        subkeys.append(Ki)
        log.append(
            f"Vòng {round_idx}: LS({sh}) -> KL{round_idx}={to_bit_str(KL)}, "
            f"KR{round_idx}={to_bit_str(KR)} -> K{round_idx}={to_bit_str(Ki)}"
        )

    return subkeys, log

# hàm F

def F_function(R4, Ki6, round_index, log):
    # Expand -> xor khóa -> S-box -> P-box
    log.append(f"  Đầu vào F = {to_bit_str(R4)}")

    # bước 1: Expand
    E = expand_4_to_6(R4)
    log.append(f"  Expand(đầu vào) = {to_bit_str(E)}")

    # bước 2: xor với khóa con
    X = xor_bits(E, Ki6)
    log.append(f"  XOR với K_{round_index} = {to_bit_str(Ki6)} -> {to_bit_str(X)}")

    # bước 3: S-box
    S_out = sbox_6_to_4(X)
    log.append(f"  S-box({to_bit_str(X)}) = {to_bit_str(S_out)}")

    # bước 4: P-box
    P_out = pbox_4(S_out)
    log.append(f"  P-box({to_bit_str(S_out)}) = {to_bit_str(P_out)} (F_{round_index})")

    return P_out

# mã hóa / giải mã

def tinyDES_encrypt_block(P8_str, subkeys):
    # không có IP và không đổi chỗ cuối
    # vòng i: L_i = R_(i-1), R_i = L_(i-1) xor F(R_(i-1), K_i); C = L3 || R3
    log = []
    validate_bits(P8_str, 8, "Bản rõ TinyDES")
    validate_subkeys(subkeys, 3, 6)
    P8 = to_bit_list(P8_str)
    log.append(f"Bản rõ P = {to_bit_str(P8)}")

    L = P8[:4]
    R = P8[4:]
    log.append(f"Chia: L0 = {to_bit_str(L)}, R0 = {to_bit_str(R)}")

    for i, Ki in enumerate(subkeys, start=1):
        log.append(f"\n--- Vòng Feistel {i} ---")
        F_out = F_function(R, Ki, i, log)
        new_L = R
        new_R = xor_bits(L, F_out)
        log.append(f"  L_{i} = R_{i-1} = {to_bit_str(new_L)}")
        log.append(f"  R_{i} = L_{i-1} XOR F_{i} = {to_bit_str(new_R)}")
        L, R = new_L, new_R

    C8 = L + R
    log.append(f"\nKết quả: L3 = {to_bit_str(L)}, R3 = {to_bit_str(R)}")
    log.append(f"Ciphertext C = {to_bit_str(C8)}")

    return to_bit_str(C8), log

def tinyDES_decrypt_block(C8_str, subkeys):
    # không đổi chỗ cuối nên giải mã đi ngược từng vòng, dùng K3, K2, K1
    # R_(i-1) = L_i, L_(i-1) = R_i xor F(L_i, K_i)
    log = []
    validate_bits(C8_str, 8, "Bản mã TinyDES")
    validate_subkeys(subkeys, 3, 6)
    C8 = to_bit_list(C8_str)
    log.append(f"Bản mã C = {to_bit_str(C8)}")

    L = C8[:4]
    R = C8[4:]
    log.append(f"Chia bản mã: L3 = {to_bit_str(L)}, R3 = {to_bit_str(R)}")

    for i, Ki in enumerate(reversed(subkeys), start=1):
        log.append(f"\n--- Vòng giải mã {i} (dùng K_{3 - i + 1}) ---")
        R_prev = L
        k = 4 - i
        log.append(f"  Tính F(L{k}, K{k}) với L{k}={to_bit_str(R_prev)}")
        F_out = F_function(R_prev, Ki, k, log)
        L_prev = xor_bits(R, F_out)
        log.append(f"  L{k-1} = R{k} XOR F(L{k}, K{k}) = {to_bit_str(L_prev)}")
        log.append(f"  R{k-1} = L{k} = {to_bit_str(R_prev)}")
        L, R = L_prev, R_prev

    P8 = L + R
    log.append(f"\nKết quả: L0 = {to_bit_str(L)}, R0 = {to_bit_str(R)}")
    log.append(f"Plaintext P (giải mã) = {to_bit_str(P8)}")

    return to_bit_str(P8), log
