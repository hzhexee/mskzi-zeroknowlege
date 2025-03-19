import socket
import random
import os
import hashlib
import time

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
        # Отправляем имя файла
        file_name = os.path.basename(file_path)
        client_socket.send(f"FILENAME:{file_name}".encode())
        
        # Отправляем размер файла
        file_size = os.path.getsize(file_path)
        client_socket.send(f"FILESIZE:{file_size}".encode())
        
        # Получаем подтверждение готовности
        ready = client_socket.recv(1024).decode()
        if ready != "READY":
            print(f"[КЛИЕНТ] Ошибка: сервер не готов к приему файла")
            client_socket.close()
            exit(1)
            
        # Отправляем содержимое файла
        with open(file_path, 'rb') as f:
            data = f.read(4096)
            while data:
                client_socket.send(data)
                data = f.read(4096)
                
        print(f"[КЛИЕНТ] Файл {file_name} успешно передан")
        
        # Получаем подтверждение о получении файла
        confirmation = client_socket.recv(1024).decode()
        print(f"[КЛИЕНТ] {confirmation}")
        
    except Exception as e:
        print(f"[КЛИЕНТ] Ошибка при передаче файла: {str(e)}")
else:
    print("[КЛИЕНТ] Аутентификация не удалась. Отправка файла невозможна.")

client_socket.close()