import random
from sympy import isprime, mod_inverse

# Генерация двух простых чисел p и q
def generate_prime(start=100, end=500):
    while True:
        num = random.randint(start, end)
        if isprime(num):
            return num

# Генерация ключей
def generate_keys():
    p = generate_prime()
    q = generate_prime()
    N = p * q
    s = random.randint(2, N - 1)  # Секретный ключ
    while not isprime(s):  # s должно быть взаимно простым с N
        s = random.randint(2, N - 1)
    v = pow(s, 2, N)  # Открытый ключ
    return (N, v), s  # (публичные ключи, приватный ключ)

# Шифрование ASCII-кода
def encrypt_char(m, s, N):
    return (m * pow(s, 2, N)) % N

# Расшифрование ASCII-кода
def decrypt_char(c, s, N):
    s_inv = mod_inverse(pow(s, 2, N), N)  # Обратное число
    return (c * s_inv) % N

# Шифрование текста
def encrypt_text(text, s, N):
    return [encrypt_char(ord(c), s, N) for c in text]

# Расшифрование текста
def decrypt_text(encrypted, s, N):
    return ''.join(chr(decrypt_char(c, s, N)) for c in encrypted)

# Чтение и запись в файл
def encrypt_fileFS(input_file, output_file, s, N):
    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read()
    encrypted = encrypt_text(text, s, N)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(' '.join(map(str, encrypted)))

def decrypt_fileFS(input_file, output_file, s, N):
    with open(input_file, 'r', encoding='utf-8') as f:
        encrypted = list(map(int, f.read().split()))
    decrypted = decrypt_text(encrypted, s, N)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(decrypted)

# # ==== ТЕСТ ====
# (pub_keys, secret) = generate_keys()
# N, v = pub_keys

# # print(f"Public Key (N, v): {N}, {v}")
# # print(f"Private Key (s): {secret}")

# # # Шифруем и расшифровываем строку
# # text = "Hello, World!"
# # enc_text = encrypt_text(text, secret, N)
# # dec_text = decrypt_text(enc_text, secret, N)

# # print("Original Text:", text)
# # print("Encrypted:", enc_text)
# # print("Decrypted:", dec_text)

# # Запись в файл
# encrypt_fileFS("input.txt", "encrypted.txt", secret, N)
# decrypt_fileFS("encrypted.txt", "decrypted.txt", secret, N)
