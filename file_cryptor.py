import base64
from cryptography.fernet import Fernet

def fit_key(key):
    if len(key) != 32:
        remainig_lenght = 32 - len(key)

        if remainig_lenght > 0:
            key += b"a" * remainig_lenght
        else:
            key = key[:32]
    return key

def get_key():
    key: str = input("Password: ")
    key: bytes = fit_key(key.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    with open(output_file, "wb") as f:
        f.write(encrypted_data)

def decrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

if __name__ == "__main__":
    print("File Encrypt/Decrypt")

    action = input("e - Encrypt\nd- Decrypt\n\nplease select one of the options: ")

    match action:
        case "e":
            key = get_key()
            input_file = input("input file address: ")
            output_file = input("output file address: ")
            encrypt_file(key, input_file, output_file)
        case "d":
            key = get_key()
            input_file = input("input file address: ")
            output_file = input("output file address: ")
            decrypt_file(key, input_file, output_file)
        case _:
            print("invalid option")