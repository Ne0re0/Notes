import hashlib
import os

def generate_salt():
    return os.urandom(16)

def calculate_md5_with_salt(text, salt):
    salted_text = salt + text.encode('utf-8')
    md5_hash = hashlib.md5()
    md5_hash.update(salted_text)
    return md5_hash.hexdigest()

def main():
    filename = "cleartext.txt"
    with open(filename, "r") as file:
        for line in file:
            line = line.strip() 
            salt = generate_salt()
            md5_hash = calculate_md5_with_salt(line, salt)
            print(f"{md5_hash}")

if __name__ == "__main__":
    main()
