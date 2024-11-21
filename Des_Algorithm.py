from tkinter import ttk, filedialog, messagebox, simpledialog, Tk, Text
import tkinter as tk
import PyPDF2
from reportlab.lib.pagesizes import letter
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
import textwrap
import os
import string

initial_permutation_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]
Permuted_Choice_table_1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]
shift_schedule = [1, 1, 2, 2,
                  2, 2, 2, 2,
                  1, 2, 2, 2,
                  2, 2, 2, 1]
Permuted_Choice_table_2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]
expansion_p_box_table = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]
S_boxes = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]
p_box_table = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]
Inverse_permutation_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

def initial_permutation_function(binary_representation):
    ip_result = [None] * 64
    for i in range(64):
        ip_result[i] = binary_representation[initial_permutation_table[i] - 1]
    ip_result_str = ''.join(ip_result)
    return ip_result_str

def Key_to_binary():
    original_key = 'ZAIDLATI'
    binary_representation_key = ''
    for char in original_key:
        binary_key = format(ord(char), '08b') 
        binary_representation_key += binary_key    
    return binary_representation_key

def round_keys_generation():
    binary_representation_key = Key_to_binary()
    pc1_key_str = ''.join(binary_representation_key[bit - 1] for bit in Permuted_Choice_table_1)
    c0 = pc1_key_str[:28]
    d0 = pc1_key_str[28:]
    round_keys = []
    for round_num in range(16):
        c0 = c0[shift_schedule[round_num]:] + c0[:shift_schedule[round_num]]
        d0 = d0[shift_schedule[round_num]:] + d0[:shift_schedule[round_num]]
        cd_concatenated = c0 + d0
        round_key = ''.join(cd_concatenated[bit - 1] for bit in Permuted_Choice_table_2)
        round_keys.append(round_key)
    return round_keys

def string_to_binary(user_input):
    padded_input = user_input + chr(8 - len(user_input) % 8) * (8 - len(user_input) % 8)
    binary_representation = ''.join(format(ord(char), '08b') for char in padded_input)
    return binary_representation

def binary_to_ascii(binary_str):
    ascii_str = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
    return ascii_str

def binary_to_hex(binary_str):
    hex_str = ''.join([hex(int(binary_str[i:i+4], 2))[2:] for i in range(0, len(binary_str), 4)])
    return hex_str.upper()

def hex_to_binary(hex_str):
    binary_str = ''.join([bin(int(char, 16))[2:].zfill(4) for char in hex_str])
    return binary_str

def remove_non_printable(input_string):
    printable = set(string.printable)
    cleaned_string = ''.join(filter(lambda x: x in printable, input_string))
    return cleaned_string

def encryption(user_input):
    binary_rep_of_input = string_to_binary(user_input)
    round_keys = round_keys_generation()
    ip_result_str = initial_permutation_function(binary_rep_of_input)
    lpt = ip_result_str[:32]
    rpt = ip_result_str[32:]
    for round_num in range(16):
        expanded_result = [rpt[i - 1] for i in expansion_p_box_table]
        expanded_result_str = ''.join(expanded_result)
        round_key_str = round_keys[round_num]
        xor_result_str = ''
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]
        s_box_substituted = ''
        for i in range(8):
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            col_bits = int(six_bit_groups[i][1:-1], 2)
            s_box_value = S_boxes[i][row_bits][col_bits]
            s_box_substituted += format(s_box_value, '04b')
        p_box_result = [s_box_substituted[i - 1] for i in p_box_table]
        lpt_list = list(lpt)
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]
        new_rpt_str = ''.join(new_rpt)
        lpt = rpt
        rpt = new_rpt_str
    final_result = rpt + lpt
    final_cipher = [final_result[Inverse_permutation_table[i] - 1] for i in range(64)]
    final_cipher_str = ''.join(final_cipher)
    final_cipher_ascii = binary_to_hex(final_cipher_str)
    return final_cipher_ascii

def decryption(final_cipher):
    round_keys = round_keys_generation()
    final = hex_to_binary(final_cipher)
    ip_dec_result_str = initial_permutation_function(final[:64])
    lpt = ip_dec_result_str[:32]
    rpt = ip_dec_result_str[32:]
    for round_num in range(16):
        expanded_result = [rpt[i - 1] for i in expansion_p_box_table]
        expanded_result_str = ''.join(expanded_result)
        round_key_str = round_keys[15-round_num]
        xor_result_str = ''
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]
        s_box_substituted = ''
        for i in range(8):
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            col_bits = int(six_bit_groups[i][1:-1], 2)
            s_box_value = S_boxes[i][row_bits][col_bits]
            s_box_substituted += format(s_box_value, '04b')
        p_box_result = [s_box_substituted[i - 1] for i in p_box_table]
        lpt_list = list(lpt)
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]
        new_rpt_str = ''.join(new_rpt)
        lpt = rpt
        rpt = new_rpt_str
    final_result = rpt + lpt
    final_cipher = [final_result[Inverse_permutation_table[i] - 1] for i in range(64)]
    final_cipher_str = ''.join(final_cipher)
    final_cipher_ascii = binary_to_ascii(final_cipher_str)
    return final_cipher_ascii

def text_from_pdf(input_pdf):
    text = ""
    try:
        with open(input_pdf, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    text += page_text
                else:
                    print(f"Warning: No text found on page {page_num + 1}.")
    except FileNotFoundError:
        print(f"Error: The file {input_pdf} was not found.")
    except Exception as e:
        print(f"An error occurred while reading the PDF: {e}")
    return text

def write_to_pdf(output_pdf_path, text):
    pdf_file = output_pdf_path
    c = canvas.Canvas(pdf_file, pagesize=A4)
    width, height = A4
    x = 100
    y = height - 100
    text_object = c.beginText()
    text_object.setTextOrigin(x, y)
    text_object.setFont("Helvetica", 12)
    text_object.setLeading(14)
    wrapped_lines = textwrap.wrap(text, width=70)
    for line in wrapped_lines:
        text_object.textLine(line)
    c.drawText(text_object)
    c.save()
    print(f"{pdf_file} has been created.")

def encrypt_full_string(full_text):
    result = ''
    for i in range(0, len(full_text), 8):
        chunk = full_text[i:i+8]
        result += encryption(chunk)
    return result

def decrypt_full_string(full_text):
    result = ''
    for i in range(0, len(full_text), 16):
        chunk = full_text[i:i+16]
        result += decryption(chunk)
    result = remove_non_printable(result)
    return result

root = tk.Tk()
root.title("DES Encryption and Decryption")
root.geometry("700x500")
root.resizable(False, False)

pdf_content = ""
selected_file = ""

def upload_pdf():
    global pdf_content, selected_file
    selected_file = filedialog.askopenfilename(
        title="Select a PDF file",
        filetypes=[("PDF files", "*.pdf")],
    )
    if selected_file:
        try:
            with open(selected_file, "rb") as pdf_file:
                reader = PyPDF2.PdfReader(pdf_file)
                pdf_content = ""
                for page in reader.pages:
                    pdf_content += page.extract_text() + "\n"
            pdf_textbox.delete(1.0, tk.END)
            pdf_textbox.insert(tk.END, pdf_content)
        except Exception as e:
            pdf_textbox.delete(1.0, tk.END)
            pdf_textbox.insert(tk.END, f"Error reading PDF: {e}")
            messagebox.showerror("Error", f"Error reading PDF: {e}")

def save_pdf(content, operation):
    global selected_file
    if not selected_file:
        messagebox.showwarning("No File Selected", "Please upload a PDF first.")
        return
    new_name = simpledialog.askstring("New File Name", "Enter the name for the new PDF file:")
    if not new_name:
        messagebox.showwarning("No Name", "Please enter a name for the new PDF file.")
        return
    try:
        file_parts = selected_file.split("/")
        original_name = file_parts[-1].split(".")[0]
        new_filename = f"{'/'.join(file_parts[:-1])}/{new_name}.pdf"
        c = canvas.Canvas(new_filename, pagesize=letter)
        c.setTitle(f"{operation} PDF")

        text_object = c.beginText(40, 750)
        text_object.setFont("Helvetica", 10)
        text_object.setTextOrigin(40, 750)
        wrapped_lines = textwrap.wrap(content, width=90)
        for line in wrapped_lines:
            text_object.textLine(line)
        c.drawText(text_object)
        c.save()
        messagebox.showinfo("Success", f"{operation} PDF created successfully:\n{new_filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save the {operation} file: {e}")

def encrypt():
    global pdf_content
    if not pdf_content:
        messagebox.showwarning("No Content", "Please upload a PDF before encrypting.")
        return
    try:
        encrypted_content = encrypt_full_string(pdf_content)
        output_textbox.delete(1.0, tk.END)
        output_textbox.insert(tk.END, encrypted_content)
        save_pdf(encrypted_content, "Encrypted")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt():
    global pdf_content
    if not pdf_content:
        messagebox.showwarning("No Content", "Please upload a PDF before decrypting.")
        return
    try:
        pdf_content = pdf_content.replace("\n", "")
        decrypted_content = decrypt_full_string(pdf_content)
        save_pdf(decrypted_content, "Decrypted")
        output_textbox.delete(1.0, tk.END)
        output_textbox.insert(tk.END, decrypted_content)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

############# GUI Starts from here #############
root.title("DES Algorithm")
root.geometry("600x600")
root.configure(bg="#f5f5f5")
style = ttk.Style()
style.theme_use("default")
primary_color = "#4a90e2"
secondary_color = "#ffffff"
button_color = "#50c878"
button_hover = "#45b06b"
text_color = "#333333"

style.configure(
    "TButton",
    font=("Arial", 12, "bold"),
    padding=6,
    background=button_color,
    foreground=secondary_color,
    borderwidth=0,
)
style.map(
    "TButton",
    background=[("active", button_hover)],
    foreground=[("active", secondary_color)],
)
style.configure("TLabel", font=("Arial", 12), background="#f5f5f5", foreground=text_color)

style.configure("TFrame", background=secondary_color, borderwidth=0)
header_label = ttk.Label(
    root,
    text="DES Algorithm",
    font=("Arial", 18, "bold"),
    foreground=primary_color,
)
header_label.pack(pady=15)

upload_frame = ttk.Frame(root)
upload_frame.pack(fill="x", padx=20, pady=10)
upload_button = ttk.Button(upload_frame, text="Upload PDF", command=upload_pdf)
upload_button.pack(side="left", padx=5)
pdf_textbox = Text(
    upload_frame,
    height=10,
    wrap="word",
    font=("Arial", 10),
    bg=secondary_color,
    fg=text_color,
    relief="solid",
    borderwidth=1,
)
pdf_textbox.pack(fill="both", expand=True, padx=10, pady=10)
action_frame = ttk.Frame(root)
action_frame.pack(fill="x", padx=20, pady=10)
encrypt_button = ttk.Button(action_frame, text="Encrypt", command=encrypt)
encrypt_button.pack(side="left", padx=10)
decrypt_button = ttk.Button(action_frame, text="Decrypt", command=decrypt)
decrypt_button.pack(side="left", padx=10)
output_frame = ttk.Frame(root)
output_frame.pack(fill="x", padx=20, pady=10)
output_label = ttk.Label(
    output_frame,
    text="Output:",
    font=("Arial", 12, "bold"),
    foreground=primary_color,
)
output_label.pack(anchor="w", pady=5)
output_textbox = Text(
    output_frame,
    height=10,
    wrap="word",
    font=("Arial", 10),
    bg=secondary_color,
    fg=text_color,
    relief="solid",
    borderwidth=1,
)
output_textbox.pack(fill="both", expand=True, padx=10, pady=10)
root.mainloop()