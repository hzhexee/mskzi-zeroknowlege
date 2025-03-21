import socket
import random
import os
import threading  # Добавляем модуль threading
# Import decryption modules
import crypto.fiat_shamir as fiat_shamir
import crypto.shnorr_encryption as shnorr_encryption
import crypto.guillou_quisquater as guillou_quisquater

# Создаем директорию для сохранения файлов, если она не существует
SAVE_DIR = "received_files"
if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

# Функция для обработки клиента в отдельном потоке
def handle_client(client_socket, addr):
    print(f"[СЕРВЕР] Клиент подключился: {addr}")

    try:
        # Получаем выбранный протокол
        protocol_data = client_socket.recv(1024).decode().strip()
        try:
            protocol = int(protocol_data)
            if protocol not in [1, 2, 3]:
                raise ValueError(f"Недопустимый протокол: {protocol}")
            print(f"[СЕРВЕР] Клиент {addr} выбрал протокол: {protocol}")
        except ValueError as e:
            print(f"[СЕРВЕР] Ошибка при получении протокола от {addr}: {e}")
            print(f"[СЕРВЕР] Полученные данные: '{protocol_data}'")
            client_socket.send(b"ERROR: Invalid protocol")
            client_socket.close()
            return
        
        auth_success = False
        
        if protocol == 1:  # Фиат-Шамир
            # Устанавливаем параметры криптографии
            n = 3233  # Простое число (p * q)
            V = 2197  # Открытый ключ клиента
            
            # Получаем X от клиента
            X = int(client_socket.recv(1024).decode())
            print(f"[СЕРВЕР] Получено X от {addr}: {X}")

            # Генерируем случайное e {0,1} и отправляем клиенту
            e = random.randint(0, 1)
            client_socket.send(str(e).encode())
            print(f"[СЕРВЕР] Отправлено e клиенту {addr}: {e}")

            # Получаем y от клиента
            y = int(client_socket.recv(1024).decode())
            print(f"[СЕРВЕР] Получено y от {addr}: {y}")

            # Проверяем условие y² = X * V^e mod n
            auth_success = pow(y, 2, n) == ((X % n) * pow(V, e, n)) % n
            
        elif protocol == 2:  # Шнорр
            # Параметры для протокола Шнорра
            p = 2267  # Простое число
            q = 103   # Простой делитель p-1
            g = 354   # Генератор подгруппы порядка q
            
            # Получаем открытый ключ от клиента
            y = int(client_socket.recv(1024).decode())
            
            # Получаем r
            r = int(client_socket.recv(1024).decode())
            print(f"[СЕРВЕР] Получено r от {addr}: {r}")
            
            # Отправляем случайный вызов e
            e = random.randint(1, q-1)
            client_socket.send(str(e).encode())
            print(f"[СЕРВЕР] Отправлено e клиенту {addr}: {e}")
            
            # Получаем s от клиента
            s = int(client_socket.recv(1024).decode())
            print(f"[СЕРВЕР] Получено s от {addr}: {s}")
            
            # Проверяем g^s = r * y^e mod p
            left_side = pow(g, s, p)
            right_side = (r * pow(y, e, p)) % p
            auth_success = (left_side == right_side)
            
        elif protocol == 3:  # Гиллу-Кискатер
            # Параметры для протокола Гийо-Кискатер
            n = 3233  # Модуль (p*q)
            v = 17    # Открытая экспонента
            
            # Получаем открытый ключ от клиента
            J = int(client_socket.recv(1024).decode())
            
            # Получаем X
            X = int(client_socket.recv(1024).decode())
            print(f"[СЕРВЕР] Получено X от {addr}: {X}")
            
            # Отправляем случайный вызов e
            e = random.randint(1, v-1)
            client_socket.send(str(e).encode())
            print(f"[СЕРВЕР] Отправлено e клиенту {addr}: {e}")
            
            # Получаем y от клиента
            y = int(client_socket.recv(1024).decode())
            print(f"[СЕРВЕР] Получено y от {addr}: {y}")
            
            # Проверяем y^v = X * J^e mod n
            left_side = pow(y, v, n)
            right_side = (X * pow(J, e, n)) % n
            auth_success = (left_side == right_side)
            
        if auth_success:
            client_socket.send(b"AUTH_SUCCESS")
            print(f"[СЕРВЕР] Аутентификация клиента {addr} успешна!")
            
            try:
                # Получаем имя файла
                filename_data = client_socket.recv(1024).decode()
                if not filename_data.startswith("FILENAME:"):
                    print(f"[СЕРВЕР] Ошибка от {addr}: неверный формат имени файла")
                    return
                    
                filename = filename_data.replace("FILENAME:", "")
                client_socket.send(b"OK")  # Подтверждаем получение
                
                # Получаем информацию о шифровании
                encryption_data = client_socket.recv(1024).decode()
                if not encryption_data.startswith("ENCRYPTION:"):
                    print(f"[СЕРВЕР] Ошибка от {addr}: неверный формат информации о шифровании")
                    return
                    
                encryption_info = encryption_data.replace("ENCRYPTION:", "")
                client_socket.send(b"OK")  # Подтверждаем получение
                print(f"[СЕРВЕР] Информация о шифровании от {addr}: {encryption_info}")
                
                # Получаем размер файла
                filesize_data = client_socket.recv(1024).decode()
                if not filesize_data.startswith("FILESIZE:"):
                    print(f"[СЕРВЕР] Ошибка от {addr}: неверный формат размера файла")
                    return
                    
                filesize = int(filesize_data.replace("FILESIZE:", ""))
                print(f"[СЕРВЕР] Получаю зашифрованный файл от {addr}: {filename}, размер: {filesize} байт")
                
                # Отправляем готовность к приему
                client_socket.send(b"READY")
                
                # Создаем уникальное имя файла для каждого клиента, чтобы избежать конфликтов
                client_id = f"{addr[0]}_{addr[1]}"
                encrypted_file = os.path.join(SAVE_DIR, f"{client_id}_encrypted_{filename}")
                bytes_received = 0
                
                with open(encrypted_file, 'wb') as f:
                    while bytes_received < filesize:
                        data = client_socket.recv(4096)
                        if not data:
                            break
                        f.write(data)
                        bytes_received += len(data)
                        
                print(f"[СЕРВЕР] Зашифрованный файл от {addr} получен и сохранен как {encrypted_file}")
                
                # Расшифровываем файл
                decrypted_file = os.path.join(SAVE_DIR, f"{client_id}_{filename}")
                
                # Парсим информацию о шифровании и расшифровываем соответственно
                enc_parts = encryption_info.split(":")
                
                if enc_parts[0] == "FS":  # Фиат-Шамир
                    N = int(enc_parts[1])
                    secret = int(enc_parts[2])
                    print(f"[СЕРВЕР] Расшифровка файла от {addr} с использованием Фиат-Шамир...")
                    fiat_shamir.decrypt_fileFS(encrypted_file, decrypted_file, secret, N)
                    
                elif enc_parts[0] == "SH":  # Шнорр
                    p = int(enc_parts[1])
                    g = int(enc_parts[2])
                    secret = int(enc_parts[3])
                    print(f"[СЕРВЕР] Расшифровка файла от {addr} с использованием Шнорр...")
                    shnorr_encryption.decrypt_fileSH(encrypted_file, decrypted_file, secret, g, p)
                    
                elif enc_parts[0] == "GQ":  # Гиллу-Кискатер
                    N = int(enc_parts[1])
                    v = int(enc_parts[2])
                    secret = int(enc_parts[3])
                    print(f"[СЕРВЕР] Расшифровка файла от {addr} с использованием Гиллу-Кискатер...")
                    guillou_quisquater.decrypt_fileGQ(encrypted_file, decrypted_file, v, N)
                
                # Удаляем зашифрованный файл
                os.remove(encrypted_file)
                
                print(f"[СЕРВЕР] Файл от {addr} успешно расшифрован и сохранен как {decrypted_file}")
                
                # Отправляем подтверждение
                client_socket.send(f"FILE_RECEIVED: Файл {filename} успешно получен и расшифрован".encode())
                
            except Exception as e:
                print(f"[СЕРВЕР] Ошибка при обработке файла от {addr}: {str(e)}")
                client_socket.send(f"ERROR: {str(e)}".encode())
            
        else:
            client_socket.send(b"AUTH_FAILED")
            print(f"[СЕРВЕР] Аутентификация клиента {addr} провалена!")
            
    except Exception as e:
        print(f"[СЕРВЕР] Ошибка с клиентом {addr}: {str(e)}")
    finally:
        client_socket.close()
        print(f"[СЕРВЕР] Соединение с клиентом {addr} закрыто")

# Запуск TCP-сервера
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 8080))
server_socket.listen(5)

print("[СЕРВЕР] Ожидание клиентов...")

try:
    while True:
        client_socket, addr = server_socket.accept()
        # Запуск нового потока для обработки клиента
        client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_thread.daemon = True  # Поток завершится, когда завершится основной поток
        client_thread.start()
        print(f"[СЕРВЕР] Запущен новый поток для клиента {addr}")
except KeyboardInterrupt:
    print("[СЕРВЕР] Завершение работы сервера...")
finally:
    server_socket.close()