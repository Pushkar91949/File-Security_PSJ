import hashlib
import os

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as file:
            # Read the file in chunks to avoid loading the entire file into memory
            for chunk in iter(lambda: file.read(4096), b''):
                sha256_hash.update(chunk)
    except IOError:
        print("Error: Failed to open the file.")
        return None
    
    return sha256_hash.hexdigest()

def store_hash(file_path):
    current_hash = calculate_hash(file_path)
    
    if current_hash is not None:
        with open('stored_hash.txt', 'w') as hash_file:
            hash_file.write(current_hash)
        print("Hash value stored for future integrity checks.")

def check_integrity(file_path):
    stored_hash = read_stored_hash()
    
    if stored_hash is not None:
        current_hash = calculate_hash(file_path)
        if current_hash is not None:
            if current_hash == stored_hash:
                print("File integrity verified. The file has not been tampered with.")
            else:
                print("File integrity compromised. The file has been modified.")

def read_stored_hash():
    if os.path.exists('stored_hash.txt'):
        with open('stored_hash.txt', 'r') as hash_file:
            stored_hash = hash_file.read().strip()
        return stored_hash
    else:
        print("Stored hash value not found.")
        return None

def main():
    file_path = input("Enter the path to the file: ")
    
    if not os.path.exists(file_path):
        print("File not found.")
        return
    
    if not os.path.isfile(file_path):
        print("Invalid file path.")
        return
    
    if not os.access(file_path, os.R_OK):
        print("Permission denied to read the file.")
        return
    
    if not os.path.exists('stored_hash.txt'):
        store_hash(file_path)
    else:
        check_integrity(file_path)

if __name__ == '__main__':
    main()
