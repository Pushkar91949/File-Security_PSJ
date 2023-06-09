import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, 'rb') as file:
            # Read the file in chunks to avoid loading the entire file into memory
            for chunk in iter(lambda: file.read(4096), b''):
                sha256_hash.update(chunk)
    except IOError:
        messagebox.showerror("Error", "Failed to open the file.")
        return None

    return sha256_hash.hexdigest()

def store_hash(file_path):
    current_hash = calculate_hash(file_path)

    if current_hash is not None:
        hash_filename = get_hash_filename(file_path)
        with open(hash_filename, 'w') as hash_file:
            hash_file.write(current_hash)

def check_integrity(file_path):
    stored_hash = read_stored_hash(file_path)

    if stored_hash is not None:
        current_hash = calculate_hash(file_path)
        if current_hash is not None:
            if current_hash == stored_hash:
                messagebox.showinfo("Integrity Check", "File integrity verified. The file has not been tampered with.")
            else:
                messagebox.showwarning("Integrity Check", "File integrity compromised. The file has been modified.")

def read_stored_hash(file_path):
    hash_filename = get_hash_filename(file_path)
    if os.path.exists(hash_filename):
        with open(hash_filename, 'r') as hash_file:
            stored_hash = hash_file.read().strip()
        return stored_hash
    else:
        return None

def browse_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(tk.END, file_path)

def run_integrity_check():
    file_path = file_entry.get()

    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File not found.")
        return

    if not os.path.isfile(file_path):
        messagebox.showerror("Error", "Invalid file path.")
        return

    if not os.access(file_path, os.R_OK):
        messagebox.showerror("Error", "Permission denied to read the file.")
        return

    hash_filename = get_hash_filename(file_path)
    if os.path.exists(hash_filename):
        check_integrity(file_path)
    else:
        store_hash(file_path)
        messagebox.showinfo("Success", "Hash value stored for future integrity checks.")

def get_hash_filename(file_path):
    return file_path + ".hash"

# Create the main window
window = tk.Tk()
window.title("File Integrity Checker")
window.geometry("400x200")

# Styling
window.configure(bg="#f0f0f0")
#window.iconbitmap("icon.ico")

# File Selection
file_label = tk.Label(window, text="File:", bg="#f0f0f0")
file_label.pack()

file_entry = tk.Entry(window, width=40)
file_entry.pack(pady=5)

browse_button = tk.Button(window, text="Browse", command=browse_file, height=2, font=("Arial", 12))
browse_button.pack()

# Integrity Check Button
check_button = tk.Button(window, text="Check Integrity", command=run_integrity_check, bg="#4CAF50", fg="white", height=2, font=("Arial", 12))
check_button.pack(pady=10)

# Run the main event loop
window.mainloop()
