import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from . import cipher_library as library
import threading
import queue
import time

# hàm dựng giao diện 

def make_title(parent, text):
    label = tk.Label(parent, text=text)
    label.pack(anchor="w", padx=10, pady=(10, 4))

def make_input_frame(parent):
    frame = tk.Frame(parent, bd=2, relief=tk.GROOVE, padx=10, pady=8)
    frame.pack(fill="x", padx=10, pady=4)
    return frame

def make_entry(frame, row, label_text, width):
    label = tk.Label(frame, text=label_text)
    label.grid(row=row, column=0, sticky="w", pady=3)
    entry = tk.Entry(frame, width=width)
    entry.grid(row=row, column=1, sticky="w", padx=6, pady=3)
    return entry

def make_text_box(parent, height):
    box = scrolledtext.ScrolledText(parent, height=height, wrap=tk.WORD)
    box.pack(fill="both", expand=True, padx=10, pady=4)
    return box

def make_result_label(parent):
    label = tk.Label(parent, text="", justify="left")
    label.pack(anchor="w", padx=10, pady=4)
    return label

def write_text(box, text):
    box.delete("1.0", tk.END)
    box.insert(tk.END, text)

def read_text(box):
    return box.get("1.0", "end-1c")

def show_error(message):
    messagebox.showerror("Lỗi", message)


# khung DES nhập văn bản/tệp

def make_des_panel(parent, title, encrypt_command, decrypt_command, choose_command, clear_command):
    panel = {}
    panel["key_type"] = tk.StringVar(value="hex")
    panel["file_data"] = None

    make_title(parent, title)
    frame = make_input_frame(parent)

    tk.Label(frame, text="Kiểu khóa:").grid(row=0, column=0, sticky="w")
    key_type_frame = tk.Frame(frame)
    key_type_frame.grid(row=0, column=1, sticky="w", padx=6)
    hex_choice = tk.Radiobutton(key_type_frame, text="16 ký tự hex", variable=panel["key_type"], value="hex")
    hex_choice.pack(side="left")
    text_choice = tk.Radiobutton(key_type_frame, text="8 byte UTF-8", variable=panel["key_type"], value="text")
    text_choice.pack(side="left", padx=10)

    panel["key_entry"] = make_entry(frame, 1, "Khóa K:", 26)

    tk.Label(frame, text="Tệp .txt:").grid(row=2, column=0, sticky="w", pady=3)
    file_frame = tk.Frame(frame)
    file_frame.grid(row=2, column=1, sticky="w", padx=6)
    tk.Button(file_frame, text="Chọn tệp...", command=choose_command).pack(side="left")
    tk.Button(file_frame, text="Bỏ tệp", command=clear_command).pack(side="left", padx=6)
    panel["file_label"] = tk.Label(file_frame, text="(chưa chọn, dùng ô dữ liệu bên dưới)")
    panel["file_label"].pack(side="left", padx=6)

    button_frame = tk.Frame(frame)
    button_frame.grid(row=0, column=2, rowspan=3, padx=20)
    tk.Button(button_frame, text="Mã hóa", command=encrypt_command).pack(fill="x", pady=2)
    tk.Button(button_frame, text="Giải mã", command=decrypt_command).pack(fill="x", pady=2)

    tk.Label(parent, text="Dữ liệu (mã hóa: văn bản; giải mã: chuỗi hex bản mã)").pack(anchor="w", padx=10)
    panel["input_box"] = make_text_box(parent, 5)

    panel["output_title"] = tk.Label(parent, text="Kết quả")
    panel["output_title"].pack(anchor="w", padx=10)
    panel["output_box"] = make_text_box(parent, 6)
    panel["info_label"] = make_result_label(parent)
    actions = tk.Frame(parent)
    actions.pack(fill="x", padx=10, pady=4)
    tk.Button(actions, text="Dùng kết quả làm đầu vào",
              command=lambda: use_output(panel)).pack(side="left")
    tk.Button(actions, text="Lưu kết quả...",
              command=lambda: save_output(panel)).pack(side="left", padx=6)
    return panel


def choose_file(panel):
    path = filedialog.askopenfilename(filetypes=[("Tệp văn bản", "*.txt"), ("Tất cả", "*.*")])
    if path == "":
        return
    try:
        with open(path, "rb") as file:
            panel["file_data"] = file.read()
    except OSError as error:
        show_error(str(error))
        return
    file_name = path.replace("\\", "/").split("/")[-1]
    panel["file_label"].config(text=file_name)


def clear_file(panel):
    panel["file_data"] = None
    panel["file_label"].config(text="(chưa chọn, dùng ô dữ liệu bên dưới)")

def run_des(panel, decrypt, use_standard):
    key_bytes, error = library.read_des_key(panel["key_entry"].get(), panel["key_type"].get())
    if error:
        show_error(error)
        return

    if panel["file_data"] is not None:
        data = panel["file_data"]
    else:
        data = read_text(panel["input_box"]).encode("utf-8")

    def finished(answer):
        result, error = answer
        if error:
            show_error(error)
            return
        panel["output_title"].config(text="Bản rõ" if decrypt else "Bản mã (hex)")
        panel["saved_bytes"] = result["raw_output"] if decrypt else result["output"].encode("ascii")
        write_text(panel["output_box"], result["output"])
        panel["info_label"].config(text=f"Số khối 64 bit: {result['blocks']}   |   "
                                         f"Thời gian chạy: {result['milliseconds']:.3f} ms")
    run_background(lambda: library.des_text(data, key_bytes, decrypt, use_standard),
                   finished, panel["info_label"])


def use_output(panel):
    clear_file(panel)
    write_text(panel["input_box"], read_text(panel["output_box"]))


def save_output(panel):
    if "saved_bytes" not in panel:
        show_error("Hãy mã hóa hoặc giải mã trước khi lưu.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".txt")
    if path:
        try:
            with open(path, "wb") as file:
                file.write(panel["saved_bytes"])
        except OSError as error:
            show_error(str(error))

busy = False
cancel_attack = threading.Event()


def run_background(work, on_done, status_label=None):
    global busy
    if busy:
        show_error("Một tác vụ đang chạy. Hãy chờ hoặc hủy vét cạn.")
        return
    busy = True
    results = queue.Queue()
    start = time.perf_counter()
    def worker():
        try:
            results.put((True, work()))
        except Exception as error:
            results.put((False, str(error)))
    def poll():
        global busy
        try:
            ok, value = results.get_nowait()
        except queue.Empty:
            if status_label is not None:
                status_label.config(text=f"Đang chạy: {time.perf_counter()-start:.1f} giây...")
            window.after(80, poll)
            return
        busy = False
        if ok:
            on_done(value)
        else:
            if status_label is not None:
                status_label.config(text="Tác vụ thất bại.")
            show_error(value)
    threading.Thread(target=worker, daemon=True).start()
    poll()


# TinyDES

def tinydes_encrypt():
    tinydes_run(0)


def tinydes_decrypt():
    tinydes_run(1)


def tinydes_run(decrypt):
    trace, milliseconds, error = library.tinydes_run(tinydes_block_entry.get(), tinydes_key_entry.get(), decrypt)
    if error:
        show_error(error)
        return

    if decrypt == 1:
        name = "Bản rõ P"
    else:
        name = "Bản mã C"
    output_text = library.binary(trace.out, 8) + " (hex " + library.number_to_hex(trace.out, 2) + ")"
    tinydes_result_label.config(text=name + " = " + output_text +
                                     "   |   Thời gian chạy: " + str(round(milliseconds, 3)) + " ms")
    write_text(tinydes_steps_box, library.tinydes_steps(trace, decrypt))


def build_tinydes_tab(tab):
    global tinydes_block_entry, tinydes_key_entry, tinydes_result_label, tinydes_steps_box

    frame = make_input_frame(tab)
    tinydes_block_entry = make_entry(frame, 0, "Khối vào (8 bít hoặc 2 ký tự hex):", 16)
    tinydes_key_entry = make_entry(frame, 1, "Khóa K (8 bít hoặc 2 ký tự hex):", 16)

    button_frame = tk.Frame(frame)
    button_frame.grid(row=0, column=2, rowspan=2, padx=20)
    tk.Button(button_frame, text="Mã hóa", command=tinydes_encrypt).pack(fill="x", pady=2)
    tk.Button(button_frame, text="Giải mã", command=tinydes_decrypt).pack(fill="x", pady=2)

    tinydes_result_label = make_result_label(tab)
    tk.Label(tab, text="Các bước trung gian").pack(anchor="w", padx=10)
    tinydes_steps_box = make_text_box(tab, 24)


# DES

def group_encrypt():
    run_des(group_panel, 0, False)


def group_decrypt():
    run_des(group_panel, 1, False)


def group_choose_file():
    choose_file(group_panel)


def group_clear_file():
    clear_file(group_panel)


def group_block_encrypt():
    group_block_run(0)


def group_block_decrypt():
    group_block_run(1)


def group_block_run(decrypt):
    result, error = library.group_one_block(group_block_entry.get(), group_block_key_entry.get(), decrypt)
    if error:
        show_error(error)
        return

    if decrypt == 1:
        name = "Bản rõ (hex) = "
    else:
        name = "Bản mã (hex) = "
    group_block_result_label.config(text=name + result)
    details = tk.Toplevel(window)
    details.title("DES — log sinh khóa và 16 vòng")
    details.geometry("1000x700")
    box = make_text_box(details, 32)
    box.configure(font=("Courier New", 10))
    write_text(box, library.des_block_steps(group_block_entry.get(), group_block_key_entry.get(), decrypt))


def build_group_tab(tab):
    global group_panel, group_block_entry, group_block_key_entry, group_block_result_label

    make_title(tab, "Một khối 64 bít (nhập hex, không đệm), dùng để đối chiếu test vector")
    frame = make_input_frame(tab)
    group_block_entry = make_entry(frame, 0, "Khối vào (16 ký tự hex):", 22)
    group_block_key_entry = make_entry(frame, 1, "Khóa K (16 ký tự hex):", 22)
    button_frame = tk.Frame(frame)
    button_frame.grid(row=0, column=2, rowspan=2, padx=20)
    tk.Button(button_frame, text="Mã hóa", command=group_block_encrypt).pack(fill="x", pady=2)
    tk.Button(button_frame, text="Giải mã", command=group_block_decrypt).pack(fill="x", pady=2)
    group_block_result_label = make_result_label(tab)

    ttk.Separator(tab).pack(fill="x", padx=10, pady=4)

    group_panel = make_des_panel(tab, "Văn bản / tệp .txt (ECB, đệm PKCS#7)",
                                 group_encrypt, group_decrypt, group_choose_file, group_clear_file)


# kiểm thử bằng thư viện chuẩn

def test_one_block():
    try:
        library.require_standard()
    except ValueError as error:
        show_error(str(error))
        return
    standard_result, error = library.standard_one_block(test_plaintext_entry.get(), test_key_entry.get())
    if error:
        show_error(error)
        return
    group_result, error = library.group_one_block(test_plaintext_entry.get(), test_key_entry.get(), 0)

    if standard_result == group_result:
        verdict = "KHỚP"
    else:
        verdict = "KHÔNG KHỚP"
    test_result_label.config(text="Thư viện chuẩn: " + standard_result + "\n" +
                                  "Thuật toán nhóm: " + group_result + "\n" +
                                  "Kết luận: " + verdict)


def test_encrypt():
    run_des(test_panel, 0, True)


def test_decrypt():
    run_des(test_panel, 1, True)


def test_choose_file():
    choose_file(test_panel)


def test_clear_file():
    clear_file(test_panel)


def build_test_tab(tab):
    global test_plaintext_entry, test_key_entry, test_result_label, test_panel

    make_title(tab, "Kiểm thử một khối 64 bít: so sánh thư viện chuẩn PyCryptodome với thuật toán nhóm")
    frame = make_input_frame(tab)
    test_plaintext_entry = make_entry(frame, 0, "Bản rõ (16 ký tự hex):", 22)
    test_key_entry = make_entry(frame, 1, "Khóa K (16 ký tự hex):", 22)
    tk.Button(frame, text="Chạy", command=test_one_block).grid(row=0, column=2, rowspan=2, padx=20)
    test_result_label = make_result_label(tab)

    ttk.Separator(tab).pack(fill="x", padx=10, pady=4)

    test_panel = make_des_panel(tab, "Kiểm thử văn bản / tệp .txt bằng thư viện chuẩn (ECB, đệm PKCS#7)",
                                test_encrypt, test_decrypt, test_choose_file, test_clear_file)


# vét cạn

def attack_tinydes():
    found_keys, error = library.tinydes_bruteforce(brute_plaintext_entry.get(), brute_ciphertext_entry.get())
    if error:
        show_error(error)
        return

    if len(found_keys) == 0:
        keys_text = "không có"
    else:
        keys_text = ", ".join(found_keys)
    brute_result_label.config(text="Đã thử 256 khóa, tìm được " + str(len(found_keys)) + " khóa:\n" + keys_text)


def attack_des():
    unknown_bits_text = unknown_bits_box.get()
    if not unknown_bits_text.isdigit():
        show_error("Số bit chưa biết N phải là số từ 8 đến 20.")
        return

    if busy:
        show_error("Một tác vụ đang chạy.")
        return
    n = int(unknown_bits_text)
    if not 8 <= n <= 20:
        show_error("Số bit chưa biết N phải từ 8 đến 20.")
        return
    plaintext, key = des_plaintext_entry.get(), des_key_entry.get()
    cancel_attack.clear()
    write_text(des_brute_box, f"Đang thử tối đa {2**n:,} khóa. Có thể bấm Hủy.")
    run_background(lambda: library.des_bruteforce(plaintext, key, n, cancel_attack),
                   finish_attack_des, attack_status)


def finish_attack_des(answer):
    result, error = answer
    if error:
        attack_status.config(text="Tác vụ thất bại.")
        show_error(error)
        return
    attack_status.config(text="Đã hủy" if result["cancelled"] else "Hoàn tất")
    text = ""
    text += "Bản rõ P            = " + result["plaintext"] + "\n"
    text += "Bản mã C = DES(P,K) = " + result["ciphertext"] + "\n"
    text += "\n"
    text += "Khóa kẻ tấn công biết ('?' là " + str(result["unknown_bits"]) + " bit chưa biết,\n"
    text += "bit cuối mỗi byte là bit chẵn lẻ):\n"
    text += "  " + result["known_key"] + "\n"
    text += "\n"
    text += "Số khóa đã thử      : " + str(result["tried"]) + "\n"
    text += "Số khóa thỏa mãn    : " + str(result["found_count"]) + "\n"
    text += "Khóa tìm được       : " + result["found_key"] + "\n"
    text += "Tìm thấy ở lần thử  : " + str(result["found_index"]) + "\n"
    text += "Thời gian           : " + str(result["seconds"]) + " giây\n"
    text += "Tốc độ              : " + str(result["speed"]) + " khóa/giây\n"
    text += "\n"
    text += "Ước tính với DES đầy đủ (2^56 khóa) ở tốc độ này:\n"
    text += "  Thử hết            : " + str(result["full_years"]) + " năm\n"
    text += "  Trung bình (1/2)   : " + str(result["average_years"]) + " năm\n"
    text += "\nƯớc tính chỉ theo tốc độ bản Python trên máy hiện tại; không đại diện mọi cách triển khai."
    write_text(des_brute_box, text)


def build_bruteforce_tab(tab):
    global brute_plaintext_entry, brute_ciphertext_entry, brute_result_label
    global des_plaintext_entry, des_key_entry, unknown_bits_box, des_brute_box, attack_status

    left = tk.Frame(tab)
    left.pack(side="left", fill="both", expand=True)
    right = tk.Frame(tab)
    right.pack(side="left", fill="both", expand=True)

    make_title(left, "Vét cạn TinyDES (2^8 = 256 khóa)")
    frame = make_input_frame(left)
    brute_plaintext_entry = make_entry(frame, 0, "Bản rõ P:", 12)
    brute_ciphertext_entry = make_entry(frame, 1, "Bản mã C:", 12)
    tk.Button(frame, text="Tấn công", command=attack_tinydes).grid(row=0, column=2, rowspan=2, padx=16)
    brute_result_label = make_result_label(left)


    make_title(right, "Vét cạn DES rút gọn (chưa biết N bit khóa)")
    frame = make_input_frame(right)
    des_plaintext_entry = make_entry(frame, 0, "Bản rõ P (hex):", 20)
    des_key_entry = make_entry(frame, 1, "Khóa thật K (hex):", 20)

    tk.Label(frame, text="Số bit chưa biết N:").grid(row=2, column=0, sticky="w", pady=3)
    unknown_bits_box = tk.Spinbox(frame, from_=8, to=20, width=5)
    unknown_bits_box.grid(row=2, column=1, sticky="w", padx=6)

    tk.Button(frame, text="Tấn công", command=attack_des).grid(row=0, column=2, rowspan=3, padx=16)
    tk.Button(right, text="Hủy vét cạn DES", command=cancel_attack.set).pack(anchor="w", padx=10)
    attack_status = make_result_label(right)
    des_brute_box = make_text_box(right, 20)


# cửa sổ chính

def main():
    global window
    window = tk.Tk()
    window.title("Hệ mã khối TinyDES và DES")
    window.geometry("1100x800")
    
    notebook = ttk.Notebook(window)
    notebook.pack(fill="both", expand=True, padx=8, pady=8)
    
    tinydes_tab = tk.Frame(notebook)
    group_tab = tk.Frame(notebook)
    test_tab = tk.Frame(notebook)
    bruteforce_tab = tk.Frame(notebook)
    
    notebook.add(tinydes_tab, text="  TinyDES   ")
    notebook.add(group_tab, text="  DES  ")
    notebook.add(test_tab, text="  Kiểm thử  ")
    notebook.add(bruteforce_tab, text="  Tấn công vét cạn  ")
    
    build_tinydes_tab(tinydes_tab)
    build_group_tab(group_tab)
    build_test_tab(test_tab)
    build_bruteforce_tab(bruteforce_tab)
    
    for entry, value in [
        (tinydes_block_entry, "01011100"), (tinydes_key_entry, "10011110"),
        (group_block_entry, "0123456789ABCDEF"), (group_block_key_entry, "133457799BBCDFF1"),
        (test_plaintext_entry, "0123456789ABCDEF"), (test_key_entry, "133457799BBCDFF1"),
        (des_plaintext_entry, "0123456789ABCDEF"), (des_key_entry, "133457799BBCDFF1"),
        (brute_plaintext_entry, "5C")]:
        entry.insert(0, value)
    trace, _, _ = library.tinydes_run("5C", "9E", 0)
    brute_ciphertext_entry.insert(0, library.number_to_hex(trace.out, 2))
    for panel in (group_panel, test_panel):
        panel["key_entry"].insert(0, "133457799BBCDFF1")
        write_text(panel["input_box"], "Xin chào! Đây là bài tập DES.")
    window.minsize(1000, 760)
    window.mainloop()


if __name__ == "__main__":
    main()
