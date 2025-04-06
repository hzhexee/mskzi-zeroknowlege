import sys
import os
import socket
import threading
import queue
import time
import random
from datetime import datetime

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QPushButton, QLineEdit, QTextEdit, QTabWidget, 
                            QTreeWidget, QTreeWidgetItem, QMessageBox, QGroupBox,
                            QFormLayout, QFrame, QSplitter)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot, QSize
from PyQt6.QtGui import QPalette, QColor, QFont

# Импортируем модули криптографии
import crypto.fiat_shamir as fiat_shamir
import crypto.shnorr_encryption as shnorr_encryption
import crypto.guillou_quisquater as guillou_quisquater

# Директория для сохранения файлов
SAVE_DIR = "received_files"
if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

class ServerGUI(QMainWindow):
    # Сигналы для безопасного обновления GUI из других потоков
    log_signal = pyqtSignal(str)
    clients_update_signal = pyqtSignal()
    files_update_signal = pyqtSignal()
    status_update_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Сервер с нулевым разглашением - GUI")
        self.resize(800, 600)
        
        # Переменные для управления сервером
        self.server_running = False
        self.server_socket = None
        self.server_thread = None
        self.client_threads = []
        self.log_queue = queue.Queue()
        self.clients = {}  # для хранения информации о клиентах
        
        # Порт сервера (по умолчанию 8080)
        self.port = "8080"
        
        # Создание интерфейса
        self.create_widgets()
        
        # Подключение сигналов
        self.log_signal.connect(self.append_log)
        self.clients_update_signal.connect(self._update_clients_list_gui)
        self.files_update_signal.connect(self.refresh_files_list)
        self.status_update_signal.connect(self.update_status_bar)
        
        # Запуск таймера для обработки логов
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.process_log_queue)
        self.log_timer.start(100)
        
        # Применяем темную тему
        self.apply_dark_theme()
    
    def apply_dark_theme(self):
        """Применяем темную тему к приложению"""
        app = QApplication.instance()
        
        # Основные цвета темной темы
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(35, 35, 35))
        
        # Применяем палитру
        app.setPalette(dark_palette)
        
        # Дополнительные стили
        style_sheet = """
        QMainWindow {
            background-color: #353535;
        }
        QWidget {
            background-color: #353535;
            color: #ffffff;
        }
        QPushButton {
            background-color: #444444;
            color: white;
            border: 1px solid #555555;
            border-radius: 3px;
            padding: 5px 15px;
            margin: 2px;
        }
        QPushButton:hover {
            background-color: #666666;
        }
        QPushButton:pressed {
            background-color: #777777;
        }
        QPushButton:disabled {
            background-color: #323232;
            color: #656565;
        }
        QLineEdit {
            background-color: #232323;
            color: white;
            border: 1px solid #555555;
            border-radius: 3px;
            padding: 2px;
        }
        QTextEdit {
            background-color: #232323;
            color: white;
            border: 1px solid #555555;
        }
        QTabWidget::pane {
            border: 1px solid #555555;
            background-color: #353535;
        }
        QTabBar::tab {
            background-color: #353535;
            color: #ffffff;
            padding: 8px 15px;
            border: 1px solid #555555;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        QTabBar::tab:selected {
            background-color: #444444;
            border-bottom: none;
        }
        QTabBar::tab:!selected {
            margin-top: 2px;
            background-color: #232323;
        }
        QTreeWidget {
            background-color: #232323;
            color: #ffffff;
            border: 1px solid #555555;
            alternate-background-color: #353535;
        }
        QTreeWidget::item {
            padding: 5px;
            border-bottom: 1px solid #444444;
        }
        QTreeWidget::item:selected {
            background-color: #2a82da;
            color: #ffffff;
        }
        QHeaderView::section {
            background-color: #444444;
            color: white;
            padding: 5px;
            border: 1px solid #555555;
        }
        QGroupBox {
            border: 1px solid #555555;
            border-radius: 3px;
            margin-top: 1ex;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 5px;
            color: #ffffff;
        }
        QStatusBar {
            background-color: #232323;
            color: #ffffff;
        }
        """
        app.setStyleSheet(style_sheet)

    def create_widgets(self):
        """Создание GUI-элементов"""
        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Панель настроек сервера
        settings_group = QGroupBox("Настройки сервера")
        settings_layout = QHBoxLayout(settings_group)
        
        # Порт сервера
        port_label = QLabel("Порт:")
        self.port_entry = QLineEdit(self.port)
        self.port_entry.setMaximumWidth(100)
        
        # Кнопки управления сервером
        self.start_button = QPushButton("Запустить сервер")
        self.start_button.clicked.connect(self.start_server)
        
        self.stop_button = QPushButton("Остановить сервер")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setEnabled(False)
        
        # Добавляем элементы в панель настроек
        settings_layout.addWidget(port_label)
        settings_layout.addWidget(self.port_entry)
        settings_layout.addWidget(self.start_button)
        settings_layout.addWidget(self.stop_button)
        settings_layout.addStretch()
        
        # Разделительная линия
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        
        # Вкладки для информации
        self.tab_widget = QTabWidget()
        
        # Вкладка логов
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        self.tab_widget.addTab(log_tab, "Логи сервера")
        
        # Вкладка клиентов
        clients_tab = QWidget()
        clients_layout = QVBoxLayout(clients_tab)
        self.clients_tree = QTreeWidget()
        self.clients_tree.setHeaderLabels(["IP-адрес", "Порт", "Протокол", "Статус", "Время подключения"])
        self.clients_tree.setAlternatingRowColors(True)
        self.clients_tree.setColumnWidth(0, 120)
        self.clients_tree.setColumnWidth(1, 70)
        self.clients_tree.setColumnWidth(2, 100)
        self.clients_tree.setColumnWidth(3, 100)
        self.clients_tree.setColumnWidth(4, 150)
        clients_layout.addWidget(self.clients_tree)
        self.tab_widget.addTab(clients_tab, "Подключенные клиенты")
        
        # Вкладка файлов
        files_tab = QWidget()
        files_layout = QVBoxLayout(files_tab)
        self.files_tree = QTreeWidget()
        self.files_tree.setHeaderLabels(["Имя файла", "Размер", "Клиент", "Время получения"])
        self.files_tree.setAlternatingRowColors(True)
        self.files_tree.setColumnWidth(0, 200)
        self.files_tree.setColumnWidth(1, 100)
        self.files_tree.setColumnWidth(2, 150)
        self.files_tree.setColumnWidth(3, 150)
        files_layout.addWidget(self.files_tree)
        
        # Кнопка обновления списка файлов
        refresh_files_button = QPushButton("Обновить список файлов")
        refresh_files_button.clicked.connect(self.refresh_files_list)
        files_layout.addWidget(refresh_files_button)
        
        self.tab_widget.addTab(files_tab, "Полученные файлы")
        
        # Статусная строка
        self.statusBar().showMessage("Сервер не запущен")
        
        # Добавляем все элементы в главный лейаут
        main_layout.addWidget(settings_group)
        main_layout.addWidget(separator)
        main_layout.addWidget(self.tab_widget, 1)  # 1 - растягивается по вертикали
        
    def log(self, message):
        """Добавляет сообщение в очередь логов"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"[{timestamp}] {message}")
    
    def process_log_queue(self):
        """Обрабатывает очередь логов и обновляет GUI"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_signal.emit(message)
                self.log_queue.task_done()
        except queue.Empty:
            pass
    
    @pyqtSlot(str)
    def append_log(self, message):
        """Добавляет сообщение в лог-виджет"""
        self.log_text.append(message)
        # Прокрутка до конца
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    @pyqtSlot(str)
    def update_status_bar(self, message):
        """Обновляет статусную строку"""
        self.statusBar().showMessage(message)
    
    def start_server(self):
        """Запускает сервер"""
        if self.server_running:
            return
        
        try:
            port = int(self.port_entry.text())
            if port < 1 or port > 65535:
                raise ValueError("Порт должен быть между 1 и 65535")
            
            self.server_thread = threading.Thread(target=self.run_server, args=(port,))
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.server_running = True
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_update_signal.emit(f"Сервер запущен на порту {port}")
            self.log(f"Сервер запущен на порту {port}")
            
        except ValueError as e:
            QMessageBox.critical(self, "Ошибка", f"Некорректный порт: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить сервер: {str(e)}")
    
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
            self.clients_tree.clear()
            self.clients = {}
            
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_update_signal.emit("Сервер остановлен")
            self.log("Сервер остановлен")
            
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка при остановке сервера: {str(e)}")
    
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
                    self.clients_update_signal.emit()
                    
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
                self.clients_update_signal.emit()
                
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
                e = random.randint(0, 1)
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
                e = random.randint(1, q-1)
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
                e = random.randint(1, v-1)
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
                self.clients_update_signal.emit()
                
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
                    self.files_update_signal.emit()
                    
                    # Отправляем подтверждение
                    client_socket.send(f"FILE_RECEIVED: Файл {filename} успешно получен и расшифрован".encode())
                    
                except Exception as e:
                    self.log(f"Ошибка при обработке файла от {addr}: {str(e)}")
                    client_socket.send(f"ERROR: {str(e)}".encode())
                
            else:
                self.clients[client_id]["status"] = "Ошибка аутентификации"
                self.clients_update_signal.emit()
                
                client_socket.send(b"AUTH_FAILED")
                self.log(f"Аутентификация клиента {addr} провалена!")
                
        except Exception as e:
            self.log(f"Ошибка с клиентом {addr}: {str(e)}")
        finally:
            # Удаляем клиента из списка
            if client_id in self.clients:
                del self.clients[client_id]
                self.clients_update_signal.emit()
                
            client_socket.close()
            self.log(f"Соединение с клиентом {addr} закрыто")
    
    @pyqtSlot()
    def _update_clients_list_gui(self):
        """Обновляет список клиентов в GUI"""
        self.clients_tree.clear()
        
        for client_id, client_info in self.clients.items():
            addr = client_info["addr"]
            protocol = client_info["protocol"]
            status = client_info["status"]
            connected_time = client_info["connected_time"]
            
            item = QTreeWidgetItem([
                addr[0], 
                str(addr[1]), 
                protocol, 
                status, 
                connected_time
            ])
            
            self.clients_tree.addTopLevelItem(item)
    
    @pyqtSlot()
    def refresh_files_list(self):
        """Обновляет список полученных файлов"""
        self.files_tree.clear()
        
        try:
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
                    
                    item = QTreeWidgetItem([filename, size_str, client, modified_time])
                    self.files_tree.addTopLevelItem(item)
        except Exception as e:
            self.log(f"Ошибка при обновлении списка файлов: {str(e)}")
    
    def closeEvent(self, event):
        """Обработчик закрытия окна"""
        if self.server_running:
            reply = QMessageBox.question(
                self, 
                "Подтверждение", 
                "Сервер запущен. Вы уверены, что хотите закрыть приложение?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_server()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ServerGUI()
    window.show()
    sys.exit(app.exec())
