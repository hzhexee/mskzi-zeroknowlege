import random
from sympy import isprime, primitive_root, mod_inverse

# Генерация простого числа p
def generate_prime(start=1000, end=5000):
    while True:
        num = random.randint(start, end)
        if isprime(num):
            return num

# Генерация ключей
def generate_keys():
    p = generate_prime()
    g = primitive_root(p)  # Выбираем первообразный корень
    x = random.randint(2, p - 2)  # Приватный ключ
    y = pow(g, x, p)  # Публичный ключ
    return (p, g, y), x

# Шифрование символа
def encrypt_char(m, x, g, p):
    return (m * pow(g, x, p)) % p

# Расшифрование символа
def decrypt_char(c, x, g, p):
    g_x_inv = mod_inverse(pow(g, x, p), p)  # Обратное число (g^x)^-1 mod p
    return (c * g_x_inv) % p

# Шифрование текста
def encrypt_text(text, x, g, p):
    return [encrypt_char(ord(c), x, g, p) for c in text]

# Расшифрование текста
def decrypt_text(encrypted, x, g, p):
    return ''.join(chr(decrypt_char(c, x, g, p)) for c in encrypted)

# Чтение и запись в файл
def encrypt_fileSH(input_file, output_file, x, g, p):
    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read()
    encrypted = encrypt_text(text, x, g, p)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(' '.join(map(str, encrypted)))

def decrypt_fileSH(input_file, output_file, x, g, p):
    with open(input_file, 'r', encoding='utf-8') as f:
        encrypted = list(map(int, f.read().split()))
    decrypted = decrypt_text(encrypted, x, g, p)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(decrypted)

# # ==== ТЕСТ ====
# (pub_keys, secret) = generate_keys()
# p, g, y = pub_keys

# print(f"Public Key (p, g, y): {p}, {g}, {y}")
# print(f"Private Key (x): {secret}")

# # Шифруем и расшифровываем строку
# text = "Hello, World!"
# enc_text = encrypt_text(text, secret, g, p)
# dec_text = decrypt_text(enc_text, secret, g, p)

# print("Original Text:", text)
# print("Encrypted:", enc_text)
# print("Decrypted:", dec_text)

# # Запись в файл
# encrypt_fileSH("input.txt", "encrypted.txt", secret, g, p)
# decrypt_fileSH("encrypted.txt", "decrypted.txt", secret, g, p)
