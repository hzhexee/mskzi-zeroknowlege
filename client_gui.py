import sys
import os
import socket
import random
import time
import threading
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QLabel, QPushButton, QLineEdit, QTextEdit, QRadioButton,
                           QButtonGroup, QFileDialog, QProgressBar, QMessageBox,
                           QGroupBox, QFormLayout, QFrame, QSplitter)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QPalette, QColor, QFont

# Импортируем модули криптографии
import crypto.fiat_shamir as fiat_shamir
import crypto.shnorr_encryption as shnorr_encryption
import crypto.guillou_quisquater as guillou_quisquater

class ClientGUI(QMainWindow):
    # Сигналы для обновления GUI из других потоков
    log_signal = pyqtSignal(str)
    status_update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    auth_status_signal = pyqtSignal(bool)
    
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Клиент с нулевым разглашением - GUI")
        self.resize(700, 500)
        
        # Переменные для соединения
        self.client_socket = None
        self.file_path = None
        self.authentication_success = False
        
        # Создание интерфейса
        self.create_widgets()
        
        # Подключение сигналов
        self.log_signal.connect(self.append_log)
        self.status_update_signal.connect(self.update_status_bar)
        self.progress_signal.connect(self.update_progress)
        self.auth_status_signal.connect(self.authentication_status_changed)
        
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
        QRadioButton {
            color: white;
            spacing: 5px;
        }
        QRadioButton::indicator {
            width: 15px;
            height: 15px;
        }
        QRadioButton::indicator:checked {
            background-color: #2a82da;
            border: 2px solid #232323;
            border-radius: 8px;
        }
        QRadioButton::indicator:unchecked {
            background-color: #232323;
            border: 2px solid #555555;
            border-radius: 8px;
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
        QProgressBar {
            border: 1px solid #555555;
            border-radius: 3px;
            background-color: #232323;
            text-align: center;
            color: white;
        }
        QProgressBar::chunk {
            background-color: #2a82da;
            width: 10px;
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
        
        # Панель настроек подключения
        connection_group = QGroupBox("Настройки подключения")
        connection_layout = QHBoxLayout(connection_group)
        
        # IP-адрес и порт
        form_layout = QFormLayout()
        self.ip_entry = QLineEdit("127.0.0.1")
        self.port_entry = QLineEdit("8080")
        self.port_entry.setMaximumWidth(100)
        form_layout.addRow("IP-адрес:", self.ip_entry)
        form_layout.addRow("Порт:", self.port_entry)
        connection_layout.addLayout(form_layout)
        
        # Протоколы аутентификации
        protocol_group = QGroupBox("Протокол аутентификации")
        protocol_layout = QVBoxLayout(protocol_group)
        
        self.protocol_group = QButtonGroup(self)
        self.rb_fiat_shamir = QRadioButton("Фиат-Шамир")
        self.rb_fiat_shamir.setChecked(True)  # По умолчанию
        self.rb_shnorr = QRadioButton("Шнорр")
        self.rb_guillou = QRadioButton("Гиллу-Кискатер")
        
        self.protocol_group.addButton(self.rb_fiat_shamir, 1)
        self.protocol_group.addButton(self.rb_shnorr, 2)
        self.protocol_group.addButton(self.rb_guillou, 3)
        
        protocol_layout.addWidget(self.rb_fiat_shamir)
        protocol_layout.addWidget(self.rb_shnorr)
        protocol_layout.addWidget(self.rb_guillou)
        
        connection_layout.addWidget(protocol_group)
        
        # Выбор файла и подключение
        file_connect_layout = QVBoxLayout()
        
        # Выбор файла
        file_layout = QHBoxLayout()
        self.file_path_entry = QLineEdit()
        self.file_path_entry.setPlaceholderText("Путь к файлу...")
        self.file_path_entry.setReadOnly(True)
        
        browse_button = QPushButton("Обзор...")
        browse_button.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path_entry)
        file_layout.addWidget(browse_button)
        file_connect_layout.addLayout(file_layout)
        
        # Кнопки подключения и отправки
        buttons_layout = QHBoxLayout()
        self.connect_button = QPushButton("Подключиться")
        self.connect_button.clicked.connect(self.connect_to_server)
        
        self.send_button = QPushButton("Отправить файл")
        self.send_button.clicked.connect(self.send_file)
        self.send_button.setEnabled(False)  # Активируется после аутентификации
        
        buttons_layout.addWidget(self.connect_button)
        buttons_layout.addWidget(self.send_button)
        file_connect_layout.addLayout(buttons_layout)
        
        connection_layout.addLayout(file_connect_layout)
        
        # Разделительная линия
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        
        # Лог событий
        log_group = QGroupBox("Журнал событий")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        # Прогресс-бар
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(QLabel("Прогресс:"))
        progress_layout.addWidget(self.progress_bar)
        
        # Добавляем все элементы в главный лейаут
        main_layout.addWidget(connection_group)
        main_layout.addWidget(separator)
        main_layout.addWidget(log_group, 1)  # 1 - растягивается по вертикали
        main_layout.addLayout(progress_layout)
        
        # Статусная строка
        self.statusBar().showMessage("Клиент не подключен")
    
    def log(self, message):
        """Добавляет сообщение в лог с временной меткой"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_signal.emit(f"[{timestamp}] {message}")
    
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
    
    @pyqtSlot(int)
    def update_progress(self, value):
        """Обновляет прогресс-бар"""
        self.progress_bar.setValue(value)
    
    @pyqtSlot(bool)
    def authentication_status_changed(self, success):
        """Обрабатывает изменение статуса аутентификации"""
        self.authentication_success = success
        self.send_button.setEnabled(success)
        if success:
            self.status_update_signal.emit("Аутентификация успешна. Готов к отправке файла")
            self.connect_button.setEnabled(False)
        else:
            self.status_update_signal.emit("Аутентификация не удалась")
    
    def browse_file(self):
        """Открывает диалог выбора файла"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл для отправки", "", "Все файлы (*.*)"
        )
        if file_path:
            self.file_path = file_path
            self.file_path_entry.setText(file_path)
            self.log(f"Выбран файл: {file_path}")
    
    def get_selected_protocol(self):
        """Возвращает выбранный протокол"""
        return self.protocol_group.checkedId()
    
    def connect_to_server(self):
        """Подключается к серверу и выполняет аутентификацию"""
        # Проверяем, выбран ли файл
        if not self.file_path:
            QMessageBox.warning(self, "Предупреждение", "Выберите файл для отправки")
            return
        
        # Получаем настройки подключения
        ip = self.ip_entry.text().strip()
        try:
            port = int(self.port_entry.text().strip())
            if port < 1 or port > 65535:
                raise ValueError("Порт должен быть между 1 и 65535")
        except ValueError as e:
            QMessageBox.critical(self, "Ошибка", f"Некорректный порт: {str(e)}")
            return
        
        # Запускаем подключение в отдельном потоке
        threading.Thread(target=self.connect_thread, args=(ip, port)).start()
    
    def connect_thread(self, ip, port):
        """Поток для подключения и аутентификации"""
        try:
            # Создаем сокет и подключаемся к серверу
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, port))
            self.status_update_signal.emit(f"Подключено к {ip}:{port}")
            self.log(f"Подключено к серверу {ip}:{port}")
            
            # Получаем выбранный протокол
            protocol = self.get_selected_protocol()
            protocol_names = {1: "Фиат-Шамир", 2: "Шнорр", 3: "Гиллу-Кискатер"}
            self.log(f"Выбран протокол: {protocol_names.get(protocol)}")
            
            # Отправляем протокол серверу
            self.client_socket.send(str(protocol).encode())
            time.sleep(0.1)  # Небольшая задержка
            
            # Аутентификация с использованием выбранного протокола
            auth_success = False
            
            if protocol == 1:  # Фиат-Шамир
                auth_success = self.authenticate_fiat_shamir()
            elif protocol == 2:  # Шнорр
                auth_success = self.authenticate_shnorr()
            elif protocol == 3:  # Гиллу-Кискатер
                auth_success = self.authenticate_guillou_quisquater()
            
            # Обновляем статус аутентификации
            self.auth_status_signal.emit(auth_success)
            
        except Exception as e:
            self.log(f"Ошибка при подключении: {str(e)}")
            self.status_update_signal.emit(f"Ошибка: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
    
    def authenticate_fiat_shamir(self):
        """Аутентификация по протоколу Фиат-Шамир"""
        try:
            # Устанавливаем параметры
            n = 3233  # Простое число (p * q)
            S = 123   # Закрытый ключ клиента
            V = pow(S, 2, n)  # Открытый ключ
            
            # Генерируем случайное r
            r = random.randint(1, n-1)
            X = pow(r, 2, n)  # X = r^2 mod n
            
            # Отправляем X
            self.client_socket.send(str(X).encode())
            self.log(f"Отправлено X: {X}")
            
            # Получаем e
            e = int(self.client_socket.recv(1024).decode())
            self.log(f"Получено e: {e}")
            
            # Вычисляем y = r * S^e mod n
            y = (r * pow(S, e, n)) % n
            self.client_socket.send(str(y).encode())
            self.log(f"Отправлено y: {y}")
            
            # Получаем результат аутентификации
            result = self.client_socket.recv(1024).decode()
            self.log(f"Ответ сервера: {result}")
            
            return result == "AUTH_SUCCESS"
        
        except Exception as e:
            self.log(f"Ошибка при аутентификации (Фиат-Шамир): {str(e)}")
            return False
    
    def authenticate_shnorr(self):
        """Аутентификация по протоколу Шнорр"""
        try:
            # Параметры протокола Шнорра
            p = 2267  # Простое число
            q = 103   # Простой делитель p-1
            g = 354   # Генератор подгруппы порядка q
            x = 47    # Закрытый ключ (x < q)
            y = pow(g, x, p)  # Открытый ключ
            
            # Отправляем открытый ключ
            self.client_socket.send(str(y).encode())
            
            # Генерируем случайное k < q
            k = random.randint(1, q-1)
            r = pow(g, k, p)
            
            # Отправляем r
            self.client_socket.send(str(r).encode())
            self.log(f"Отправлено r: {r}")
            
            # Получаем случайный вызов e от сервера
            e = int(self.client_socket.recv(1024).decode())
            self.log(f"Получено e: {e}")
            
            # Вычисляем s = (k + e*x) mod q
            s = (k + e * x) % q
            self.client_socket.send(str(s).encode())
            self.log(f"Отправлено s: {s}")
            
            # Получаем результат аутентификации
            result = self.client_socket.recv(1024).decode()
            self.log(f"Ответ сервера: {result}")
            
            return result == "AUTH_SUCCESS"
        
        except Exception as e:
            self.log(f"Ошибка при аутентификации (Шнорр): {str(e)}")
            return False
    
    def authenticate_guillou_quisquater(self):
        """Аутентификация по протоколу Гиллу-Кискатер"""
        try:
            # Параметры протокола Гиллу-Кискатер
            n = 3233  # Модуль (p*q)
            v = 17    # Открытая экспонента (взаимно простая с φ(n))
            s = 621   # Секретный ключ
            J = pow(s, v, n)  # Открытый ключ
            
            # Отправляем открытый ключ
            self.client_socket.send(str(J).encode())
            
            # Генерируем случайное r
            r = random.randint(1, n-1)
            X = pow(r, v, n)
            
            # Отправляем X
            self.client_socket.send(str(X).encode())
            self.log(f"Отправлено X: {X}")
            
            # Получаем случайный вызов e от сервера
            e = int(self.client_socket.recv(1024).decode())
            self.log(f"Получено e: {e}")
            
            # Вычисляем y = (r * s^e) mod n
            y = (r * pow(s, e, n)) % n
            self.client_socket.send(str(y).encode())
            self.log(f"Отправлено y: {y}")
            
            # Получаем результат аутентификации
            result = self.client_socket.recv(1024).decode()
            self.log(f"Ответ сервера: {result}")
            
            return result == "AUTH_SUCCESS"
        
        except Exception as e:
            self.log(f"Ошибка при аутентификации (Гиллу-Кискатер): {str(e)}")
            return False
    
    def send_file(self):
        """Отправляет файл на сервер"""
        if not self.authentication_success or not self.client_socket or not self.file_path:
            QMessageBox.warning(self, "Предупреждение", "Необходимо аутентифицироваться и выбрать файл")
            return
        
        # Запускаем отправку в отдельном потоке
        threading.Thread(target=self.send_file_thread).start()
    
    def send_file_thread(self):
        """Поток для отправки файла"""
        try:
            protocol = self.get_selected_protocol()
            self.log(f"Начинаем передачу файла: {self.file_path}")
            
            # Обновляем прогресс-бар
            self.progress_signal.emit(10)
            
            # Создаем временный файл для шифрования
            temp_encrypted_file = "temp_encrypted.txt"
            
            # Шифруем файл в зависимости от выбранного протокола
            self.log(f"Шифруем файл...")
            self.progress_signal.emit(20)
            
            if protocol == 1:  # Фиат-Шамир
                # Генерируем ключи
                (pub_keys, secret) = fiat_shamir.generate_keys()
                N, v = pub_keys
                # Шифруем файл
                fiat_shamir.encrypt_fileFS(self.file_path, temp_encrypted_file, secret, N)
                # Сохраняем ключи для передачи серверу
                encryption_info = f"FS:{N}:{secret}"
            
            elif protocol == 2:  # Шнорр
                # Генерируем ключи
                (pub_keys, secret) = shnorr_encryption.generate_keys()
                p, g, y = pub_keys
                # Шифруем файл
                shnorr_encryption.encrypt_fileSH(self.file_path, temp_encrypted_file, secret, g, p)
                # Сохраняем ключи для передачи серверу
                encryption_info = f"SH:{p}:{g}:{secret}"
            
            elif protocol == 3:  # Гиллу-Кискатер
                # Генерируем ключи
                (pub_keys, secret) = guillou_quisquater.generate_keys()
                N, v = pub_keys
                # Шифруем файл
                guillou_quisquater.encrypt_fileGQ(self.file_path, temp_encrypted_file, secret, N)
                # Сохраняем ключи для передачи серверу
                encryption_info = f"GQ:{N}:{v}:{secret}"
            
            self.log(f"Файл успешно зашифрован")
            self.progress_signal.emit(40)
            
            # Отправляем имя файла
            file_name = os.path.basename(self.file_path)
            self.client_socket.send(f"FILENAME:{file_name}".encode())
            response = self.client_socket.recv(1024).decode()  # Получаем подтверждение
            
            self.progress_signal.emit(50)
            
            # Отправляем информацию о шифровании
            self.client_socket.send(f"ENCRYPTION:{encryption_info}".encode())
            response = self.client_socket.recv(1024).decode()  # Получаем подтверждение
            
            self.progress_signal.emit(60)
            
            # Отправляем размер зашифрованного файла
            file_size = os.path.getsize(temp_encrypted_file)
            self.client_socket.send(f"FILESIZE:{file_size}".encode())
            
            # Получаем подтверждение готовности
            ready = self.client_socket.recv(1024).decode()
            if ready != "READY":
                self.log(f"Ошибка: сервер не готов к приему файла")
                self.progress_signal.emit(0)
                return
            
            self.progress_signal.emit(70)
                
            # Отправляем содержимое зашифрованного файла
            bytes_sent = 0
            with open(temp_encrypted_file, 'rb') as f:
                data = f.read(4096)
                while data:
                    self.client_socket.send(data)
                    bytes_sent += len(data)
                    # Обновляем прогресс
                    progress = 70 + (bytes_sent / file_size) * 20  # От 70% до 90%
                    self.progress_signal.emit(int(progress))
                    data = f.read(4096)
                    
            self.log(f"Зашифрованный файл {file_name} успешно передан")
            self.progress_signal.emit(90)
            
            # Удаляем временный зашифрованный файл
            os.remove(temp_encrypted_file)
            
            # Получаем подтверждение о получении файла
            confirmation = self.client_socket.recv(1024).decode()
            self.log(f"{confirmation}")
            
            self.progress_signal.emit(100)
            self.status_update_signal.emit("Файл успешно отправлен и расшифрован на сервере")
            
        except Exception as e:
            self.log(f"Ошибка при отправке файла: {str(e)}")
            self.status_update_signal.emit(f"Ошибка: {str(e)}")
            self.progress_signal.emit(0)
        finally:
            # Закрываем соединение
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            # Сбрасываем статус аутентификации
            self.auth_status_signal.emit(False)
            # Восстанавливаем кнопку подключения
            self.connect_button.setEnabled(True)
    
    def closeEvent(self, event):
        """Обработчик закрытия окна"""
        if self.client_socket:
            reply = QMessageBox.question(
                self, 
                "Подтверждение", 
                "Соединение активно. Вы уверены, что хотите закрыть приложение?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                if self.client_socket:
                    self.client_socket.close()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ClientGUI()
    window.show()
    sys.exit(app.exec())
