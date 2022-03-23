import os
import base64
import getpass
import argparse

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_salt():
    salt = os.urandom(16) # Salt needs to be 16-byte long
    salt = base64.b64encode(salt).decode('utf-8')
    print(f"!!!IMPORTANT!!! Save this. You'll need it (salt) when decrypting the file: {salt}")

    return salt


def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key is 32-byte long
        salt=salt.encode(),
        iterations=390000,  # As recommended by Django as of November 2021 https://github.com/django/django/blob/main/django/contrib/auth/hashers.py
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt(filename, password, salt):
    key = generate_key(password, salt)

    encyptor = Fernet(key)
    with open(filename) as f:
        content = f.read()
        return encyptor.encrypt(content.encode()).decode()


def decrypt(filename, password, salt):
    key = generate_key(password, salt)

    encyptor = Fernet(key)
    with open(filename) as f:
        content = f.read()
        return encyptor.decrypt(content.encode()).decode()


def export(output_file, data):
    with open(output_file, "w+") as f:
        f.write(data)


def check_input_file(input_file):
    if os.path.exists(input_file):
        return True

    else:
        raise Exception(f"{input_file} doesn't exists.")


def read_password_from_user():
    return getpass.getpass("Password: ")


def read_salt_from_user():
    return getpass.getpass("Salt: ")


def run_command(func, args, user_provides_salt=False):
    input_file = os.path.normpath(args.input)
    output_file = os.path.normpath(args.output)

    if check_input_file(input_file):
        password = read_password_from_user()
        salt = read_salt_from_user() if user_provides_salt else generate_salt()

        export(output_file, func(input_file, password, salt))


def encrypt_file(args):
    run_command(encrypt, args, False)


def decrypt_file(args):
    run_command(decrypt, args, True)


def io_parser(parser):
    parser.add_argument(
        "--input", "-i", help="Input file path.", type=str, required=True
    )
    parser.add_argument(
        "--output", "-o", help="Output file path.", type=str, required=True
    )


def parse_cli():
    parser = argparse.ArgumentParser(description="Encrypt/decrypt file with password.")

    subparsers = parser.add_subparsers(help="sub-command help")
    encrypt_parser = subparsers.add_parser(
        "encrypt", description="Encrypt file with password."
    )
    encrypt_parser.set_defaults(func=encrypt_file)
    io_parser(encrypt_parser)

    decrypt_parser = subparsers.add_parser(
        "decrypt", description="Decrypt file with password."
    )
    decrypt_parser.set_defaults(func=decrypt_file)
    io_parser(decrypt_parser)

    return parser.parse_args()


def main():
    args = parse_cli()
    args.func(args)


if __name__ == "__main__":
    main()
