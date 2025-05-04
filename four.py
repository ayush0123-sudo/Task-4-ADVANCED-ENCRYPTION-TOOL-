import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import os

# File Integrity Checker
def calculate_file_hash(file_path):
    hash_algo = hashlib.sha256()  # SHA-256 algorithm
    with open(file_path, 'rb') as file:
        file_data = file.read()
        hash_algo.update(file_data)
    return hash_algo.hexdigest()

def check_file_integrity(file_path, prev_hash):
    current_hash = calculate_file_hash(file_path)
    if current_hash != prev_hash:
        print("\n⚠️  Warning: File has been modified!")
    else:
        print("\n✅ File is intact and not modified.")

# AES-256 Encryption and Decryption
def generate_key(password, salt=None):
    if salt is None:
        salt = get_random_bytes(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    return key, salt

def encrypt_file(file_path, password):
    key, salt = generate_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    pad_len = 16 - (len(file_data) % 16)
    file_data += bytes([pad_len]) * pad_len
    
    encrypted_data = cipher.encrypt(file_data)
    
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(salt + cipher.iv + encrypted_data)

    print(f"\n🔒 File encrypted successfully: {encrypted_file_path}")
    return encrypted_file_path

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_file_data = encrypted_data[32:]
    
    key, _ = generate_key(password, salt)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_file_data)
    
    pad_len = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_len]
    
    decrypted_file_path = file_path.replace(".enc", ".dec")
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    print(f"\n🔓 File decrypted successfully: {decrypted_file_path}")
    return decrypted_file_path

# Main code
if __name__ == "__main__":
    file_path = input("📂 Enter the full path of the file: ").strip()
    password = input("🔑 Enter the password for encryption/decryption: ").strip()

    if not os.path.isfile(file_path):
        print("\n❌ Error: File not found!")
        exit()

    # Save original file hash
    original_hash = calculate_file_hash(file_path)
    print(f"\n📄 Original file hash saved: {original_hash}")

    # Encrypt the file
    encrypted_file = encrypt_file(file_path, password)

    # Check integrity of the original file (it should match original)
    check_file_integrity(file_path, original_hash)

    # Decrypt the file
    decrypted_file = decrypt_file(encrypted_file, password)

    # Check integrity of decrypted file (it should match original)
    check_file_integrity(decrypted_file, original_hash)
