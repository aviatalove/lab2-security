"""VulnLab: локальный учебный сервер с SQL Injection и IDOR. Запуск: python server.py"""
import json # чтобы сервер умел читать и отдавать данные в формате JSON
import secrets # нужен для генерации надежных случайных токенов для пользователей
import sqlite3 # встроенная база данных используемая для хранения пользователей
from http.server import BaseHTTPRequestHandler, HTTPServer # HTTPServer — слушает порт, BaseHTTPRequestHandler — обрабатывает запросы (GET, POST)
from pathlib import Path # инструмент для работы с путями к файлам (чтобы база данных создавалась в той же папке, где лежит скрипт).
from urllib.parse import urlparse, parse_qs # помогает разбирать ссылки на части

HOST, PORT = "127.0.0.1", 8000 # локальный адрес и порт, по которому будет доступен сервер
DB_FILE = Path(__file__).with_name("vulnlab.db")  # умный путь к файлу базы данных, создастся рядом с server.py
SESSIONS = {} # словарь, база данных в оперативной памяти. Здесь хранятся активные сессии

# ф-ия для подключения к базе данных
def connect_db():
    db = sqlite3.connect(DB_FILE) # открывает файл БД (или создаёт его, если файла нет)
    db.row_factory = sqlite3.Row # говорит БД возвращать данные в виде словаря
    return db # отдает открытое подключение туда, откуда вызвали функцию

# ф-ия для первичной настройки базы данных
def initialize_db():
    with connect_db() as db: # открываем подключение к базе
        # создаем таблицу пользователей и таблицу заметок, если их нет (выполняем SQL команды)
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
                title TEXT NOT NULL, body TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0: # проверяем, пустая ли таблица (если да - добавляем тестовых)
            db.executemany(
                "INSERT INTO users(username, password) VALUES (?, ?)",
                [("alice", "alice123"), ("bob", "bob123")]
            )
            db.executemany(
                "INSERT INTO notes(user_id, title, body) VALUES (?, ?, ?)",
                [(1, "Заметка Алисы", "Личная заметка Alice."),
                 (2, "Заметка Боба", "Учебная заметка Bob.")]
            )

# ф-ия для проверки логина и пароля при входе
def authenticate(username, password):
    # УЯЗВИМОСТЬ 1: SQL Injection — пользовательский ввод вставляется в SQL
    with connect_db() as db: # открываем подключение к базе данных
        query = ("SELECT id, username FROM users "
                 f"WHERE username = '{username}' AND password = '{password}'")
        return db.execute(query).fetchone()  # выполняем запрос и возвращаем первую найденную запись (или None)

# ф-ия для получения заметки по её номеру
def get_note(note_id):
    # УЯЗВИМОСТЬ 2: IDOR — не проверяется владелец запрашиваемой заметки.
    # ищем заметку по id (безопасно от SQL-инъекций, но не проверяет владельца)
    with connect_db() as db: # открываем подключение к базе данных
        return db.execute(
            "SELECT id, user_id, title, body FROM notes WHERE id = ?", (note_id,)
        ).fetchone()

# класс-обработчик. Наследуется от стандартного BaseHTTPRequestHandler, чтобы перехватывать входящие HTTP-запросы (GET, POST) и отвечать на них
class Handler(BaseHTTPRequestHandler):
    # ф-я помощник для отправки JSON-ответов клиенту
    def send_json(self, status, data, token=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8") # превращаем словарь в JSON-строку и переводим в байты
        self.send_response(status) # отправляем HTTP-статус (200 — успех, 404 — не найдено, 401 — нет доступа)
        self.send_header("Content-Type", "application/json; charset=utf-8") # сообщаем клиенту, что отправляем JSON в кодировке UTF-8
        self.send_header("Content-Length", str(len(body))) # сообщаем точный размер данных в байтах
        if token: # если нам передали токен (успешный вход)
            self.send_header("Set-Cookie", f"session={token}; HttpOnly; SameSite=Strict; Path=/") # отправляем куки с токеном и настройками безопасности
        self.end_headers() # завершаем блок заголовков
        self.wfile.write(body)  # отправляем данные клиенту

    # ф-ия для чтения JSON-данных из входящего запроса
    def read_json(self):
        length = int(self.headers.get("Content-Length", "0")) # узнаем размер тела запроса из заголовков (по умолчанию 0)
        if length > 10000: # защита от перегрузки
            raise ValueError("Слишком большой запрос")
        return json.loads(self.rfile.read(length).decode("utf-8") or "{}") # читаем данные, переводим в текст и превращаем в словарь Python (если пусто — возвращаем пустой словарь)

    # ф-ия для получения ID пользователя по его куки
    def current_user_id(self):
        for part in self.headers.get("Cookie", "").split(";"): # получаем строку кук, разбиваем по ";" и перебираем каждый кусочек
            part = part.strip() # убираем лишние пробелы по краям
            if part.startswith("session="):
                return SESSIONS.get(part.split("=", 1)[1]) # достаем токен и ищем его в нашем словаре SESSIONS
        return None

    # обрабатывает GET-запросы (когда мы открываем страницы)
    def do_GET(self):
        parsed = urlparse(self.path) # разбираем адрес на маршрут и параметры
        if parsed.path == "/": # если зашли на главную страницу...
            page = ("<h1>VulnLab</h1><p>SQL Injection и IDOR — учебная демонстрация.</p>"
                    "<p>Тестовые пользователи: alice/alice123, bob/bob123.</p>").encode() # готовим HTML-страничку
            self.send_response(200) # отправляем статус 200
            self.send_header("Content-Type", "text/html; charset=utf-8") # говорим, что это HTML
            self.send_header("Content-Length", str(len(page))) # указываем размер
            self.end_headers() # завершаем заголовки
            self.wfile.write(page) # отправляем страницу
            return

        if parsed.path == "/note":  # если запросили заметку
            user_id = self.current_user_id() # узнаем, кто это по куки

            if user_id is None: # если куки нет или она неверная
                self.send_json(401, {"error": "Сначала выполните вход"})
                return

            try: # пытаемся получить номер заметки
                note_id = int(parse_qs(parsed.query).get("id", ["0"])[0]) # достаем id из адреса и делаем из него число

            except ValueError: # если вместо числа ввели буквы
                self.send_json(400, {"error": "Некорректный id"})
                return

            note = get_note(note_id) # ищем заметку в базе по id

            if note is None: # если такой заметки нет
                self.send_json(404, {"error": "Заметка не найдена"})
                return
            # Намеренно отсутствует проверка note["user_id"] == user_id.
            self.send_json(200, dict(note)) # отправляем заметку клиенту (даже если она чужая)
            return
        self.send_json(404, {"error": "Маршрут не найден"}) # если адрес вообще непонятный — 404

    # обрабатывает POST-запросы (отправку данных на сервер)
    def do_POST(self):
        if urlparse(self.path).path != "/login": # если POST пришел НЕ на /login...
            self.send_json(404, {"error": "Маршрут не найден"})
            return

        try: # пытаемся прочитать данные от клиента
            data = self.read_json() # читаем JSON из тела запроса
            username, password = str(data.get("username", "")), str(data.get("password", "")) # достаем логин и пароль (если их нет — пустые строки)

        except (ValueError, json.JSONDecodeError): # если пришел кривой JSON
            self.send_json(400, {"error": "Некорректный JSON"})
            return

        try: # пытаемся проверить логин и пароль
            user = authenticate(username, password)  # вызываем цязвимую ф-ию (тут работает SQL-инъекция)

        except sqlite3.Error:  # если база данных выдала ошибку
            self.send_json(400, {"error": "Ошибка обработки запроса"})
            return

        if user is None: # если такого пользователя нет (пароль не подошел)
            self.send_json(401, {"error": "Неверный логин или пароль"})
            return

        token = secrets.token_urlsafe(24) # генерируем случайный токен (пропуск) для успешного входа
        SESSIONS[token] = user["id"] # сохраняем в словарь SESSIONS: токен -> ID пользователя
        self.send_json(200, {"message": "Вход выполнен", "username": user["username"]}, token) # отправляем успешный ответ и прикрепляем токен в Cookie

    # ф-ия, переопределяющая стандартный вывод логов сервера
    def log_message(self, fmt, *args):
        print("[HTTP] " + fmt % args) # выводит в консоль красивую строку лога (например, "[HTTP] GET /login 200")

 # выполняется только если мы запускаем файл напрямую (а не импортируем его)
if __name__ == "__main__":
    initialize_db() # создаем базу данных и наполняем её тестовыми пользователями
    print(f"VulnLab запущен: http://{HOST}:{PORT} (остановка: Ctrl+C)") # выводим подсказку, что сервер работает
    HTTPServer((HOST, PORT), Handler).serve_forever() # запускаем сервер и заставляем его бесконечно ждать запросы
