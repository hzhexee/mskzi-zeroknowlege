import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import queue
import time
import os
import random  # Добавлен импорт модуля random
from datetime import datetime
import sys

# Импортируем модули криптографии
import crypto.fiat_shamir as fiat_shamir
import crypto.shnorr_encryption as shnorr_encryption
import crypto.guillou_quisquater as guillou_quisquater

# Директория для сохранения файлов
SAVE_DIR = "received_files"
if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Сервер с нулевым разглашением - GUI")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Переменные для управления сервером
        self.server_running = False
        self.server_socket = None
        self.server_thread = None
        self.client_threads = []
        self.log_queue = queue.Queue()
        self.clients = {}  # для хранения информации о клиентах
        
        # Порт сервера
        self.port_var = tk.StringVar(value="8080")
        
        # Создание интерфейса
        self.create_widgets()
        
        # Запуск процесса обработки логов
        self.root.after(100, self.process_log_queue)

    def create_widgets(self):
        # Создаем главный фрейм
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Верхняя панель с настройками сервера
        settings_frame = ttk.LabelFrame(main_frame, text="Настройки сервера", padding="5")
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Порт сервера
        ttk.Label(settings_frame, text="Порт:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        port_entry = ttk.Entry(settings_frame, textvariable=self.port_var, width=10)
        port_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Кнопки управления сервером
        self.start_button = ttk.Button(settings_frame, text="Запустить сервер", command=self.start_server)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)
        
        self.stop_button = ttk.Button(settings_frame, text="Остановить сервер", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)
        
        # Добавляем отступ между верхней и нижней панелями
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=5, pady=5)
        
        # Панель с информацией
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Создаем вкладки
        tab_control = ttk.Notebook(info_frame)
        
        # Вкладка логов
        log_tab = ttk.Frame(tab_control)
        tab_control.add(log_tab, text="Логи сервера")
        
        # Вкладка клиентов
        clients_tab = ttk.Frame(tab_control)
        tab_control.add(clients_tab, text="Подключенные клиенты")
        
        # Вкладка файлов
        files_tab = ttk.Frame(tab_control)
        tab_control.add(files_tab, text="Полученные файлы")
        
        tab_control.pack(fill=tk.BOTH, expand=True)
        
        # Настройка вкладки логов
        self.log_text = scrolledtext.ScrolledText(log_tab, wrap=tk.WORD, width=80, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
        # Настройка вкладки клиентов
        self.clients_tree = ttk.Treeview(clients_tab, columns=("ip", "port", "protocol", "status", "connected_time"), show="headings")
        self.clients_tree.heading("ip", text="IP-адрес")
        self.clients_tree.heading("port", text="Порт")
        self.clients_tree.heading("protocol", text="Протокол")
        self.clients_tree.heading("status", text="Статус")
        self.clients_tree.heading("connected_time", text="Время подключения")
        
        self.clients_tree.column("ip", width=120, anchor=tk.CENTER)
        self.clients_tree.column("port", width=70, anchor=tk.CENTER)
        self.clients_tree.column("protocol", width=100, anchor=tk.CENTER)
        self.clients_tree.column("status", width=100, anchor=tk.CENTER)
        self.clients_tree.column("connected_time", width=150, anchor=tk.CENTER)
        
        self.clients_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Настройка вкладки файлов
        self.files_tree = ttk.Treeview(files_tab, columns=("filename", "size", "client", "received_time"), show="headings")
        self.files_tree.heading("filename", text="Имя файла")
        self.files_tree.heading("size", text="Размер")
        self.files_tree.heading("client", text="Клиент")
        self.files_tree.heading("received_time", text="Время получения")
        
        self.files_tree.column("filename", width=200)
        self.files_tree.column("size", width=100, anchor=tk.CENTER)
        self.files_tree.column("client", width=150, anchor=tk.CENTER)
        self.files_tree.column("received_time", width=150, anchor=tk.CENTER)
        
        self.files_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Кнопка для обновления списка файлов
        refresh_files_button = ttk.Button(files_tab, text="Обновить список файлов", command=self.refresh_files_list)
        refresh_files_button.pack(pady=5)
        
        # Статусная строка
        self.status_var = tk.StringVar(value="Сервер не запущен")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)

    def log(self, message):
        """Добавляет сообщение в очередь логов"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"[{timestamp}] {message}")

    def process_log_queue(self):
        """Обрабатывает очередь логов и обновляет GUI"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
                self.log_queue.task_done()
        except queue.Empty:
            pass
        finally:
            # Повторяем проверку каждые 100 мс
            self.root.after(100, self.process_log_queue)

    def start_server(self):
        """Запускает сервер"""
        if self.server_running:
            return
        
        try:
            port = int(self.port_var.get())
            if port < 1 or port > 65535:
                raise ValueError("Порт должен быть между 1 и 65535")
            
            self.server_thread = threading.Thread(target=self.run_server, args=(port,))
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.server_running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_var.set(f"Сервер запущен на порту {port}")
            self.log(f"Сервер запущен на порту {port}")
            
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректный порт: {str(e)}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить сервер: {str(e)}")
    
    def stop_server(self):
        """Останавливает сервер"""
        if not self.server_running:
            return
        
        try:
            self.server_running = False
            
            # Закрываем серверный сокет
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            
            # Ждем завершения потока сервера
            if self.server_thread:
                self.server_thread.join(1.0)
                self.server_thread = None
            
            # Очищаем список клиентов
            self.clients_tree.delete(*self.clients_tree.get_children())
            self.clients = {}
            
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_var.set("Сервер остановлен")
            self.log("Сервер остановлен")
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при остановке сервера: {str(e)}")
    
    def run_server(self, port):
        """Функция для запуска сервера в отдельном потоке"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Таймаут для возможности остановки сервера
            
            self.log("Ожидание подключения клиентов...")
            
            while self.server_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    
                    # Добавляем клиента в список и создаем поток для обработки
                    client_id = f"{addr[0]}_{addr[1]}"
                    self.clients[client_id] = {
                        "addr": addr,
                        "socket": client_socket,
                        "protocol": "Неизвестно",
                        "status": "Подключен",
                        "connected_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    # Обновляем отображение клиентов
                    self.update_clients_list()
                    
                    # Запускаем поток для обработки клиента
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, addr, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.client_threads.append(client_thread)
                    
                except socket.timeout:
                    # Таймаут нужен для проверки условия выхода из цикла
                    continue
                except Exception as e:
                    if self.server_running:  # Логируем ошибку только если сервер еще запущен
                        self.log(f"Ошибка при подключении клиента: {str(e)}")
            
        except Exception as e:
            self.log(f"Ошибка сервера: {str(e)}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def handle_client(self, client_socket, addr, client_id):
        """Обработка клиента в отдельном потоке"""
        self.log(f"Клиент подключился: {addr}")
        
        try:
            # Получаем выбранный протокол
            protocol_data = client_socket.recv(1024).decode().strip()
            try:
                protocol = int(protocol_data)
                if protocol not in [1, 2, 3]:
                    raise ValueError(f"Недопустимый протокол: {protocol}")
                
                protocol_names = {1: "Фиат-Шамир", 2: "Шнорр", 3: "Гиллу-Кискатер"}
                protocol_name = protocol_names.get(protocol, "Неизвестный")
                
                # Обновляем информацию о клиенте
                self.clients[client_id]["protocol"] = protocol_name
                self.update_clients_list()
                
                self.log(f"Клиент {addr} выбрал протокол: {protocol_name}")
            except ValueError as e:
                self.log(f"Ошибка при получении протокола от {addr}: {e}")
                self.log(f"Полученные данные: '{protocol_data}'")
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
                self.log(f"Получено X от {addr}: {X}")

                # Генерируем случайное e {0,1} и отправляем клиенту
                e = random.randint(0, 1)  # Исправлено: random вместо threading
                client_socket.send(str(e).encode())
                self.log(f"Отправлено e клиенту {addr}: {e}")

                # Получаем y от клиента
                y = int(client_socket.recv(1024).decode())
                self.log(f"Получено y от {addr}: {y}")

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
                self.log(f"Получено r от {addr}: {r}")
                
                # Отправляем случайный вызов e
                e = random.randint(1, q-1)  # Исправлено: random вместо threading
                client_socket.send(str(e).encode())
                self.log(f"Отправлено e клиенту {addr}: {e}")
                
                # Получаем s от клиента
                s = int(client_socket.recv(1024).decode())
                self.log(f"Получено s от {addr}: {s}")
                
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
                self.log(f"Получено X от {addr}: {X}")
                
                # Отправляем случайный вызов e
                e = random.randint(1, v-1)  # Исправлено: random вместо threading
                client_socket.send(str(e).encode())
                self.log(f"Отправлено e клиенту {addr}: {e}")
                
                # Получаем y от клиента
                y = int(client_socket.recv(1024).decode())
                self.log(f"Получено y от {addr}: {y}")
                
                # Проверяем y^v = X * J^e mod n
                left_side = pow(y, v, n)
                right_side = (X * pow(J, e, n)) % n
                auth_success = (left_side == right_side)
            
            # Обновляем статус клиента
            if auth_success:
                self.clients[client_id]["status"] = "Аутентифицирован"
                self.update_clients_list()
                
                client_socket.send(b"AUTH_SUCCESS")
                self.log(f"Аутентификация клиента {addr} успешна!")
                
                try:
                    # Получаем имя файла
                    filename_data = client_socket.recv(1024).decode()
                    if not filename_data.startswith("FILENAME:"):
                        self.log(f"Ошибка от {addr}: неверный формат имени файла")
                        return
                        
                    filename = filename_data.replace("FILENAME:", "")
                    client_socket.send(b"OK")  # Подтверждаем получение
                    
                    # Получаем информацию о шифровании
                    encryption_data = client_socket.recv(1024).decode()
                    if not encryption_data.startswith("ENCRYPTION:"):
                        self.log(f"Ошибка от {addr}: неверный формат информации о шифровании")
                        return
                        
                    encryption_info = encryption_data.replace("ENCRYPTION:", "")
                    client_socket.send(b"OK")  # Подтверждаем получение
                    self.log(f"Информация о шифровании от {addr}: {encryption_info}")
                    
                    # Получаем размер файла
                    filesize_data = client_socket.recv(1024).decode()
                    if not filesize_data.startswith("FILESIZE:"):
                        self.log(f"Ошибка от {addr}: неверный формат размера файла")
                        return
                        
                    filesize = int(filesize_data.replace("FILESIZE:", ""))
                    self.log(f"Получаю зашифрованный файл от {addr}: {filename}, размер: {filesize} байт")
                    
                    # Отправляем готовность к приему
                    client_socket.send(b"READY")
                    
                    # Создаем уникальное имя файла для каждого клиента
                    encrypted_file = os.path.join(SAVE_DIR, f"{client_id}_encrypted_{filename}")
                    bytes_received = 0
                    
                    with open(encrypted_file, 'wb') as f:
                        while bytes_received < filesize:
                            data = client_socket.recv(4096)
                            if not data:
                                break
                            f.write(data)
                            bytes_received += len(data)
                            
                    self.log(f"Зашифрованный файл от {addr} получен и сохранен как {encrypted_file}")
                    
                    # Расшифровываем файл
                    decrypted_file = os.path.join(SAVE_DIR, f"{client_id}_{filename}")
                    
                    # Парсим информацию о шифровании и расшифровываем
                    enc_parts = encryption_info.split(":")
                    
                    if enc_parts[0] == "FS":  # Фиат-Шамир
                        N = int(enc_parts[1])
                        secret = int(enc_parts[2])
                        self.log(f"Расшифровка файла от {addr} с использованием Фиат-Шамир...")
                        fiat_shamir.decrypt_fileFS(encrypted_file, decrypted_file, secret, N)
                        
                    elif enc_parts[0] == "SH":  # Шнорр
                        p = int(enc_parts[1])
                        g = int(enc_parts[2])
                        secret = int(enc_parts[3])
                        self.log(f"Расшифровка файла от {addr} с использованием Шнорр...")
                        shnorr_encryption.decrypt_fileSH(encrypted_file, decrypted_file, secret, g, p)
                        
                    elif enc_parts[0] == "GQ":  # Гиллу-Кискатер
                        N = int(enc_parts[1])
                        v = int(enc_parts[2])
                        secret = int(enc_parts[3])
                        self.log(f"Расшифровка файла от {addr} с использованием Гиллу-Кискатер...")
                        guillou_quisquater.decrypt_fileGQ(encrypted_file, decrypted_file, v, N)
                    
                    # Удаляем зашифрованный файл
                    os.remove(encrypted_file)
                    
                    self.log(f"Файл от {addr} успешно расшифрован и сохранен как {decrypted_file}")
                    
                    # Обновляем список файлов
                    self.refresh_files_list()
                    
                    # Отправляем подтверждение
                    client_socket.send(f"FILE_RECEIVED: Файл {filename} успешно получен и расшифрован".encode())
                    
                except Exception as e:
                    self.log(f"Ошибка при обработке файла от {addr}: {str(e)}")
                    client_socket.send(f"ERROR: {str(e)}".encode())
                
            else:
                self.clients[client_id]["status"] = "Ошибка аутентификации"
                self.update_clients_list()
                
                client_socket.send(b"AUTH_FAILED")
                self.log(f"Аутентификация клиента {addr} провалена!")
                
        except Exception as e:
            self.log(f"Ошибка с клиентом {addr}: {str(e)}")
        finally:
            # Удаляем клиента из списка
            if client_id in self.clients:
                del self.clients[client_id]
                self.update_clients_list()
                
            client_socket.close()
            self.log(f"Соединение с клиентом {addr} закрыто")
    
    def update_clients_list(self):
        """Обновляет список клиентов в GUI"""
        # Выполняем обновление через главный поток, т.к. работаем с GUI
        self.root.after(0, self._update_clients_list_gui)
    
    def _update_clients_list_gui(self):
        """Вспомогательная функция для обновления GUI из главного потока"""
        # Очищаем текущий список
        self.clients_tree.delete(*self.clients_tree.get_children())
        
        # Добавляем всех клиентов
        for client_id, client_info in self.clients.items():
            addr = client_info["addr"]
            protocol = client_info["protocol"]
            status = client_info["status"]
            connected_time = client_info["connected_time"]
            
            self.clients_tree.insert(
                "", tk.END, 
                values=(addr[0], addr[1], protocol, status, connected_time)
            )
    
    def refresh_files_list(self):
        """Обновляет список полученных файлов"""
        # Очищаем текущий список
        self.files_tree.delete(*self.files_tree.get_children())
        
        try:
            # Получаем список файлов из директории
            if os.path.exists(SAVE_DIR):
                files = [f for f in os.listdir(SAVE_DIR) if not f.startswith("encrypted_")]
                
                for file in files:
                    file_path = os.path.join(SAVE_DIR, file)
                    
                    # Получаем информацию о файле
                    stat_info = os.stat(file_path)
                    size = stat_info.st_size
                    modified_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Получаем информацию о клиенте из имени файла
                    parts = file.split("_", 2)
                    if len(parts) >= 3:
                        client_ip = parts[0]
                        client_port = parts[1]
                        filename = parts[2]
                        client = f"{client_ip}:{client_port}"
                    else:
                        filename = file
                        client = "Неизвестно"
                    
                    # Форматируем размер файла
                    if size < 1024:
                        size_str = f"{size} Б"
                    elif size < 1024 * 1024:
                        size_str = f"{size/1024:.1f} КБ"
                    else:
                        size_str = f"{size/(1024*1024):.1f} МБ"
                    
                    self.files_tree.insert(
                        "", tk.END, 
                        values=(filename, size_str, client, modified_time)
                    )
        except Exception as e:
            self.log(f"Ошибка при обновлении списка файлов: {str(e)}")
    
    def on_closing(self):
        """Обработчик закрытия окна"""
        if self.server_running:
            if messagebox.askyesno("Подтверждение", "Сервер запущен. Вы уверены, что хотите закрыть приложение?"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
