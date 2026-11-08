"""VulnLab: локальный учебный сервер с SQL Injection и IDOR. Запуск: python server.py"""
import json
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HOST, PORT = "127.0.0.1", 8000
DB_FILE = Path(__file__).with_name("vulnlab.db")
SESSIONS = {}


def connect_db():
    db = sqlite3.connect(DB_FILE)
    db.row_factory = sqlite3.Row
    return db


def initialize_db():
    with connect_db() as db:
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
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            db.executemany(
                "INSERT INTO users(username, password) VALUES (?, ?)",
                [("alice", "alice123"), ("bob", "bob123")]
            )
            db.executemany(
                "INSERT INTO notes(user_id, title, body) VALUES (?, ?, ?)",
                [(1, "Заметка Алисы", "Личная заметка Alice."),
                 (2, "Заметка Боба", "Учебная заметка Bob.")]
            )


def authenticate(username, password):
    # УЯЗВИМОСТЬ 1: SQL Injection — пользовательский ввод вставляется в SQL.
    with connect_db() as db:
        query = ("SELECT id, username FROM users "
                 f"WHERE username = '{username}' AND password = '{password}'")
        return db.execute(query).fetchone()


def get_note(note_id):
    # УЯЗВИМОСТЬ 2: IDOR — не проверяется владелец запрашиваемой заметки.
    with connect_db() as db:
        return db.execute(
            "SELECT id, user_id, title, body FROM notes WHERE id = ?", (note_id,)
        ).fetchone()


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, data, token=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if token:
            self.send_header("Set-Cookie", f"session={token}; HttpOnly; SameSite=Strict; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 10000:
            raise ValueError("Слишком большой запрос")
        return json.loads(self.rfile.read(length).decode("utf-8") or "{}")

    def current_user_id(self):
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("session="):
                return SESSIONS.get(part.split("=", 1)[1])
        return None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            page = ("<h1>VulnLab</h1><p>SQL Injection и IDOR — учебная демонстрация.</p>"
                    "<p>Тестовые пользователи: alice/alice123, bob/bob123.</p>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        if parsed.path == "/note":
            user_id = self.current_user_id()
            if user_id is None:
                self.send_json(401, {"error": "Сначала выполните вход"})
                return
            try:
                note_id = int(parse_qs(parsed.query).get("id", ["0"])[0])
            except ValueError:
                self.send_json(400, {"error": "Некорректный id"})
                return
            note = get_note(note_id)
            if note is None:
                self.send_json(404, {"error": "Заметка не найдена"})
                return
            # Намеренно отсутствует проверка note["user_id"] == user_id.
            self.send_json(200, dict(note))
            return
        self.send_json(404, {"error": "Маршрут не найден"})

    def do_POST(self):
        if urlparse(self.path).path != "/login":
            self.send_json(404, {"error": "Маршрут не найден"})
            return
        try:
            data = self.read_json()
            username, password = str(data.get("username", "")), str(data.get("password", ""))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Некорректный JSON"})
            return
        try:
            user = authenticate(username, password)
        except sqlite3.Error:
            self.send_json(400, {"error": "Ошибка обработки запроса"})
            return
        if user is None:
            self.send_json(401, {"error": "Неверный логин или пароль"})
            return
        token = secrets.token_urlsafe(24)
        SESSIONS[token] = user["id"]
        self.send_json(200, {"message": "Вход выполнен", "username": user["username"]}, token)

    def log_message(self, fmt, *args):
        print("[HTTP] " + fmt % args)


if __name__ == "__main__":
    initialize_db()
    print(f"VulnLab запущен: http://{HOST}:{PORT} (остановка: Ctrl+C)")
    HTTPServer((HOST, PORT), Handler).serve_forever()
