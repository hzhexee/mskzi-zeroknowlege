import socket
import random
import os
import hashlib
import time
# Import encryption modules
import fiat_shamir
import shnorr_encryption
import guillou_quisquater

# Запрашиваем путь к файлу
file_path = input("Введите путь к файлу для отправки: ")

# Проверяем существование файла
if not os.path.exists(file_path):
    print(f"[КЛИЕНТ] Ошибка: Файл {file_path} не найден")
    exit(1)

# Выбор протокола
print("Выберите протокол аутентификации:")
print("1. Фиат-Шамир (текущий)")
print("2. Шнорр")
print("3. Гиллу-Кискатер")
protocol = int(input("Введите номер протокола (1-3): "))
# Validate input
if protocol not in [1, 2, 3]:
    print("Ошибка: Введите число от 1 до 3")
    exit(1)

# Подключаемся к серверу
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 8080))

# Отправляем выбранный протокол
client_socket.send(str(protocol).encode())
# Add a small delay or wait for acknowledgment
time.sleep(0.1)
print(f"[КЛИЕНТ] Выбран протокол: {protocol}")

# Аутентификация с использованием выбранного протокола
if protocol == 1:  # Фиат-Шамир
    # Устанавливаем параметры
    n = 3233  # Простое число (p * q)
    S = 123  # Закрытый ключ клиента
    V = pow(S, 2, n)  # Открытый ключ

    # Генерируем случайное r
    r = random.randint(1, n-1)
    X = pow(r, 2, n)  # X = r^2 mod n

    # Отправляем X
    client_socket.send(str(X).encode())
    print(f"[КЛИЕНТ] Отправлено X: {X}")

    # Получаем e
    e = int(client_socket.recv(1024).decode())
    print(f"[КЛИЕНТ] Получено e: {e}")

    # Вычисляем y = r * S^e mod n
    y = (r * pow(S, e, n)) % n
    client_socket.send(str(y).encode())
    print(f"[КЛИЕНТ] Отправлено y: {y}")

elif protocol == 2:  # Шнорр
    # Параметры протокола Шнорра
    p = 2267  # Простое число
    q = 103  # Простой делитель p-1
    g = 354  # Генератор подгруппы порядка q
    x = 47  # Закрытый ключ (x < q)
    y = pow(g, x, p)  # Открытый ключ

    # Отправляем открытый ключ
    client_socket.send(str(y).encode())
    
    # Генерируем случайное k < q
    k = random.randint(1, q-1)
    r = pow(g, k, p)
    
    # Отправляем r
    client_socket.send(str(r).encode())
    print(f"[КЛИЕНТ] Отправлено r: {r}")
    
    # Получаем случайный вызов e от сервера
    e = int(client_socket.recv(1024).decode())
    print(f"[КЛИЕНТ] Получено e: {e}")
    
    # Вычисляем s = (k + e*x) mod q
    s = (k + e * x) % q
    client_socket.send(str(s).encode())
    print(f"[КЛИЕНТ] Отправлено s: {s}")

elif protocol == 3:  # Гиллу-Кискатер
    # Параметры протокола Гиллу-Кискатер
    n = 3233  # Модуль (p*q)
    v = 17    # Открытая экспонента (взаимно простая с φ(n))
    s = 621   # Секретный ключ
    J = pow(s, v, n)  # Открытый ключ
    
    # Отправляем открытый ключ
    client_socket.send(str(J).encode())
    
    # Генерируем случайное r
    r = random.randint(1, n-1)
    X = pow(r, v, n)
    
    # Отправляем X
    client_socket.send(str(X).encode())
    print(f"[КЛИЕНТ] Отправлено X: {X}")
    
    # Получаем случайный вызов e от сервера
    e = int(client_socket.recv(1024).decode())
    print(f"[КЛИЕНТ] Получено e: {e}")
    
    # Вычисляем y = (r * s^e) mod n
    y = (r * pow(s, e, n)) % n
    client_socket.send(str(y).encode())
    print(f"[КЛИЕНТ] Отправлено y: {y}")

# Получаем ответ
result = client_socket.recv(1024).decode()
print(f"[КЛИЕНТ] Ответ от сервера: {result}")

# Если аутентификация успешна, отправляем файл
if result == "AUTH_SUCCESS":
    print(f"[КЛИЕНТ] Аутентификация успешна. Начинаем передачу файла: {file_path}")
    try:
        # Шифруем файл перед отправкой
        print(f"[КЛИЕНТ] Шифруем файл используя алгоритм {protocol}...")
        
        # Создаем временный файл для шифрования
        temp_encrypted_file = "temp_encrypted.txt"
        
        # Шифруем файл в зависимости от выбранного протокола
        if protocol == 1:  # Фиат-Шамир
            # Генерируем ключи
            (pub_keys, secret) = fiat_shamir.generate_keys()
            N, v = pub_keys
            # Шифруем файл
            fiat_shamir.encrypt_fileFS(file_path, temp_encrypted_file, secret, N)
            # Сохраняем ключи для передачи серверу
            encryption_info = f"FS:{N}:{secret}"
        
        elif protocol == 2:  # Шнорр
            # Генерируем ключи
            (pub_keys, secret) = shnorr_encryption.generate_keys()
            p, g, y = pub_keys
            # Шифруем файл
            shnorr_encryption.encrypt_fileSH(file_path, temp_encrypted_file, secret, g, p)
            # Сохраняем ключи для передачи серверу
            encryption_info = f"SH:{p}:{g}:{secret}"
        
        elif protocol == 3:  # Гиллу-Кискатер
            # Генерируем ключи
            (pub_keys, secret) = guillou_quisquater.generate_keys()
            N, v = pub_keys
            # Шифруем файл
            guillou_quisquater.encrypt_fileGQ(file_path, temp_encrypted_file, secret, N)
            # Сохраняем ключи для передачи серверу
            encryption_info = f"GQ:{N}:{v}:{secret}"
        
        print(f"[КЛИЕНТ] Файл успешно зашифрован")
        
        # Отправляем имя файла
        file_name = os.path.basename(file_path)
        client_socket.send(f"FILENAME:{file_name}".encode())
        response = client_socket.recv(1024).decode()  # Получаем подтверждение
        
        # Отправляем информацию о шифровании
        client_socket.send(f"ENCRYPTION:{encryption_info}".encode())
        response = client_socket.recv(1024).decode()  # Получаем подтверждение
        
        # Отправляем размер зашифрованного файла
        file_size = os.path.getsize(temp_encrypted_file)
        client_socket.send(f"FILESIZE:{file_size}".encode())
        
        # Получаем подтверждение готовности
        ready = client_socket.recv(1024).decode()
        if ready != "READY":
            print(f"[КЛИЕНТ] Ошибка: сервер не готов к приему файла")
            client_socket.close()
            exit(1)
            
        # Отправляем содержимое зашифрованного файла
        with open(temp_encrypted_file, 'rb') as f:
            data = f.read(4096)
            while data:
                client_socket.send(data)
                data = f.read(4096)
                
        print(f"[КЛИЕНТ] Зашифрованный файл {file_name} успешно передан")
        
        # Удаляем временный зашифрованный файл
        os.remove(temp_encrypted_file)
        
        # Получаем подтверждение о получении файла
        confirmation = client_socket.recv(1024).decode()
        print(f"[КЛИЕНТ] {confirmation}")
        
    except Exception as e:
        print(f"[КЛИЕНТ] Ошибка при передаче файла: {str(e)}")
else:
    print("[КЛИЕНТ] Аутентификация не удалась. Отправка файла невозможна.")

client_socket.close()