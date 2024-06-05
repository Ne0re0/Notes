import hashlib

def calculate_md5(text):
    md5_hash = hashlib.md5()
    md5_hash.update(text.encode('utf-8'))
    return md5_hash.hexdigest()

def main():
    filename = "cleartext.txt"
    with open(filename, "r") as file:
        for line in file:
            line = line.strip()  # Remove leading/trailing whitespaces
            md5_hash = calculate_md5(line)
            print(md5_hash)
            # print(f"MD5 hash of '{line}': {md5_hash}")

if __name__ == "__main__":
    main()
