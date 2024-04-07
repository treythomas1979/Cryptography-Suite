import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
from ftplib import FTP
import socket
import sys
import argparse
import time
from io import BytesIO

# Binary Decoder Functions
def decode_binary(binary_str):
    binary_str = binary_str.replace("\r", "").replace("\n", "").replace("\b", "")
    output_str = ""

    if len(binary_str) % 8 == 0:
        decoded_ascii = ""
        for i in range(0, len(binary_str), 8):
            decoded_char = chr(int(binary_str[i:i+8], 2))
            decoded_ascii += decoded_char
        output_str += "8-bit ASCII:\n"
        output_str += decoded_ascii
    else:
        try:
            decoded_ascii = "".join(chr(int(binary_str[i:i+7], 2)) for i in range(0, len(binary_str), 7))
            output_str += "7-bit ASCII:\n"
            output_str += decoded_ascii
        except ValueError:
            output_str += "Unable to decode as 7-bit ASCII."

    return output_str

def on_decode_click():
    binary_input = input_text.get("1.0", "end-1c")
    decoded_output = decode_binary(binary_input)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, decoded_output)

# Vigenere Cipher Functions
def vigenere_cipher(text, key, decrypt=False):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = ''.join(key.split()).upper()
    result = []
    key_position = 0

    for char in text:
        if char.isalpha():
            if char.upper() not in alphabet:
                print(f"Character not in alphabet: {char}")
                result.append(char)
                continue

            key_char = key[key_position % len(key)]
            while not key_char.isalpha():
                key_position = (key_position + 1) % len(key)
                key_char = key[key_position % len(key)]

            key_shift = alphabet.index(key_char)

            if char.isupper():
                shift = alphabet.index(char) - key_shift if decrypt else (alphabet.index(char) + key_shift) % 26
                result.append(alphabet[shift])
            elif char.islower():
                char = char.upper()
                shift = alphabet.index(char) - key_shift if decrypt else (alphabet.index(char) + key_shift) % 26
                result.append(alphabet[shift].lower())

            key_position = (key_position + 1) % len(key)
        else:
            result.append(char)
    return ''.join(result)

def on_encrypt_click():
    text_input = input_text_vigenere.get("1.0", "end-1c")
    key_input = key_entry.get()
    encrypted_output = vigenere_cipher(text_input, key_input)
    output_text_vigenere.delete("1.0", tk.END)
    output_text_vigenere.insert(tk.END, encrypted_output)

def on_decrypt_click():
    text_input = input_text_vigenere.get("1.0", "end-1c")
    key_input = key_entry.get()
    decrypted_output = vigenere_cipher(text_input, key_input, decrypt=True)
    output_text_vigenere.delete("1.0", tk.END)
    output_text_vigenere.insert(tk.END, decrypted_output)

# FTP Decoder Function
def retrieve_covert_message(IP, PORT, USER, PASSWORD, FOLDER, METHOD):
    try:
        # Connect and login to the FTP server
        ftp = FTP()
        ftp.connect(IP, PORT)
        ftp.login(USER, PASSWORD)
        ftp.set_pasv(True)

        # Navigate to the specified directory and list files
        ftp.cwd(FOLDER)
        files = []
        ftp.dir(files.append)

        # Exit the FTP server
        ftp.quit()

        # Extract and decode the covert message from file permissions
        covert_message = ""
        for file_info in files:
            # Extract file permissions from the file info
            permission_str = file_info[:10]
            # Check if the first three bits contain letters
            if not any(char.isalpha() for char in permission_str[:3]):
                decoded_char = decode_permissions(permission_str)
                covert_message += decoded_char

        # Output the covert message
        if METHOD == "7-bit":
            return covert_message

        # 10-bit extraction method
        if METHOD == "10-bit":
            # Extract and convert the permission bits to 1's and 0's
            permission_bits = ""

            for file_info in files:
                # Extract file permissions from the file info
                permission_str = file_info[:10]

                # Convert letters to '1' and '-' to '0'
                binary_str = ''.join(['1' if char.isalpha() else '0' for char in permission_str])

                # Append the binary permission bits to the result
                permission_bits += binary_str

            # Split the binary string into 7-bit chunks and convert to decimal
            decimal_permissions = [int(permission_bits[i:i+7], 2) for i in range(0, len(permission_bits), 7)]

            # Convert decimal permissions to ASCII characters and return without spaces
            ascii_message = ''.join([chr(decimal) for decimal in decimal_permissions])
            return ascii_message
    except Exception as e:
        return str(e)

# Timing Attack Function
def timing_attack(IP, PORT, median_time):
    global timings_display 

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, PORT))

    overt_message = ""
    timing_results = []

    while True:
        t0 = time.perf_counter()

        data = s.recv(4096).decode()

        t1 = time.perf_counter()

        delta = round((t1 - t0) * 1000, 3)

        timing_results.append(delta)
        overt_message += data

        # Update the timings display in real-time
        timings_display.insert(tk.END, str(delta) + "\n")
        timings_display.see(tk.END)
        root.update()  # Update the Tkinter GUI event loop

        if "EOF" in overt_message:
            break

    s.close()


    binary_timing = ['1' if ms > median_time else '0' for ms in timing_results]

    if binary_timing and binary_timing[0] == '0':
        binary_timing.pop(0)

    binary_timing_string = ''.join(binary_timing)

    eight_bit_chunks = [binary_timing_string[i:i+8] for i in range(0, len(binary_timing_string), 8)]
    ascii_characters = [chr(int(chunk, 2)) for chunk in eight_bit_chunks]

    return binary_timing_string, ascii_characters


# Function to record timings and update the output fields
def perform_timing_attack():
    IP = timing_ip_entry.get()
    try:
        PORT = int(timing_port_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Invalid port number.")
        return

    try:
        median_time = float(median_time_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Invalid median time.")
        return

    binary_timing, ascii_characters = timing_attack(IP, PORT, median_time)

    # Update the output fields with the results
    output_timing_results.delete("1.0", tk.END)
    output_timing_results.insert(tk.END, "Binary Timing Results:\n" + binary_timing)

    output_ascii_characters.delete("1.0", tk.END)
    output_ascii_characters.insert(tk.END, "ASCII Characters:\n" + ''.join(ascii_characters))


# GUI
root = tk.Tk()
root.title("Cryptography Suite")

notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True)

binary_frame = ttk.Frame(notebook)
notebook.add(binary_frame, text="Binary Decoder")

vigenere_frame = ttk.Frame(notebook)
notebook.add(vigenere_frame, text="Vigenere Cipher")

ftp_frame = ttk.Frame(notebook)
notebook.add(ftp_frame, text="Cover Message")

timing_attack_frame = ttk.Frame(notebook)
notebook.add(timing_attack_frame, text="Chat Timing")

# Binary Decoder Tab
label_input = tk.Label(binary_frame, text="Enter binary encoded message:")
label_input.pack(pady=10)
input_text = scrolledtext.ScrolledText(binary_frame, wrap=tk.WORD, width=50, height=10)
input_text.pack(pady=10)
decode_button = tk.Button(binary_frame, text="Decode", command=on_decode_click)
decode_button.pack(pady=10)
open_button_binary = tk.Button(binary_frame, text="Open File", command=lambda: open_file(input_text))
open_button_binary.pack(pady=10)
label_output = tk.Label(binary_frame, text="Decoded Message:")
label_output.pack(pady=10)
output_text = scrolledtext.ScrolledText(binary_frame, wrap=tk.WORD, width=50, height=10)
output_text.pack(pady=10)

# Vigenere Cipher Tab
label_input_vigenere = tk.Label(vigenere_frame, text="Enter the message:")
label_input_vigenere.pack(pady=10)
input_text_vigenere = scrolledtext.ScrolledText(vigenere_frame, wrap=tk.WORD, width=50, height=10)
input_text_vigenere.pack(pady=10)
label_key = tk.Label(vigenere_frame, text="Enter the Vigenere key:")
label_key.pack(pady=10)
key_entry = tk.Entry(vigenere_frame, width=50)
key_entry.pack(pady=10)
encrypt_button = tk.Button(vigenere_frame, text="Encrypt", command=on_encrypt_click)
encrypt_button.pack(pady=10)
decrypt_button = tk.Button(vigenere_frame, text="Decrypt", command=on_decrypt_click)
decrypt_button.pack(pady=10)
open_button_vigenere = tk.Button(vigenere_frame, text="Open File", command=lambda: open_file(input_text_vigenere))
open_button_vigenere.pack(pady=10)
output_text_vigenere = scrolledtext.ScrolledText(vigenere_frame, wrap=tk.WORD, width=50, height=10)
output_text_vigenere.pack(pady=10)

# FTP Decoder Tab
label_ip = tk.Label(ftp_frame, text="IP Address:")
label_ip.pack(pady=10)
ip_entry = tk.Entry(ftp_frame, width=50)
ip_entry.pack(pady=10)

label_port = tk.Label(ftp_frame, text="Port:")
label_port.pack(pady=10)
port_entry = tk.Entry(ftp_frame, width=50)
port_entry.pack(pady=10)
port_entry.insert(tk.END, "21")

label_user = tk.Label(ftp_frame, text="Username:")
label_user.pack(pady=10)
user_entry = tk.Entry(ftp_frame, width=50)
user_entry.pack(pady=10)

label_password = tk.Label(ftp_frame, text="Password:")
label_password.pack(pady=10)
password_entry = tk.Entry(ftp_frame, width=50, show="*")
password_entry.pack(pady=10)

label_folder = tk.Label(ftp_frame, text="Folder:")
label_folder.pack(pady=10)
folder_entry = tk.Entry(ftp_frame, width=50)
folder_entry.pack(pady=10)

method_var = tk.IntVar()
rb1 = tk.Radiobutton(ftp_frame, text="7-bit", variable=method_var, value=1)
rb1.pack(pady=10)
rb2 = tk.Radiobutton(ftp_frame, text="10-bit", variable=method_var, value=2)
rb2.pack(pady=10)

fetch_button = tk.Button(ftp_frame, text="Fetch Covert Message", command=lambda: fetch_and_display_covert_message())
fetch_button.pack(pady=10)

output_text_ftp = scrolledtext.ScrolledText(ftp_frame, wrap=tk.WORD, width=50, height=10)
output_text_ftp.pack(pady=10)

# Covert Chat Timings Tab
label_timing_ip = tk.Label(timing_attack_frame, text="IP Address:")
label_timing_ip.pack(pady=5)
timing_ip_entry = tk.Entry(timing_attack_frame, width=50)
timing_ip_entry.pack(pady=5)
timing_ip_entry.insert(tk.END, "138.47.99.64")

label_timing_port = tk.Label(timing_attack_frame, text="Port:")
label_timing_port.pack(pady=5)
timing_port_entry = tk.Entry(timing_attack_frame, width=50)
timing_port_entry.pack(pady=5)
timing_port_entry.insert(tk.END, "31337")

label_median_time = tk.Label(timing_attack_frame, text="Median Time:")
label_median_time.pack(pady=5)
median_time_entry = tk.Entry(timing_attack_frame, width=50)
median_time_entry.pack(pady=5)
median_time_entry.insert(tk.END, "90")

perform_attack_button = tk.Button(timing_attack_frame, text="retrieve message", command=perform_timing_attack)
perform_attack_button.pack(pady=5)

output_timing_results = scrolledtext.ScrolledText(timing_attack_frame, wrap=tk.WORD, width=50, height=10)
output_timing_results.pack(pady=5)

output_ascii_characters = scrolledtext.ScrolledText(timing_attack_frame, wrap=tk.WORD, width=50, height=10)
output_ascii_characters.pack(pady=5)

timings_display = scrolledtext.ScrolledText(timing_attack_frame, wrap=tk.WORD, width=50, height=5)
timings_display.pack(pady=5)


#Missing code here:  
def open_file(text_widget):
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r') as file:
            text_widget.delete("1.0", tk.END)
            text_widget.insert(tk.END, file.read())

def decode_permissions(permission_str):
    binary_str = ''
    for char in permission_str:
        if char == '-':
            binary_str += '0'
        else:
            binary_str += '1'
    return chr(int(binary_str, 2))

def fetch_and_display_covert_message():
    IP = ip_entry.get()
    try:
        PORT = int(port_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Invalid port number.")
        return

    USER = user_entry.get()
    PASSWORD = password_entry.get()
    FOLDER = folder_entry.get()
    METHOD = "7-bit" if method_var.get() == 1 else "10-bit"

    covert_message = retrieve_covert_message(IP, PORT, USER, PASSWORD, FOLDER, METHOD)
    output_text_ftp.delete("1.0", tk.END)
    output_text_ftp.insert(tk.END, covert_message)

root.mainloop()
