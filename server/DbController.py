import sqlite3
from flask import g

DATABASE = 'database.db'
def prepare_database():
    try:
        with sqlite3.connect('database.db') as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            cursor = conn.cursor()

            setup_command = """
            CREATE TABLE IF NOT EXISTS app_users(
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                public_key TEXT
            );

            CREATE TABLE IF NOT EXISTS messages(
                message_id INTEGER PRIMARY KEY,
                content TEXT NOT NULL,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                date_sent DATETIME NOT NULL,
                is_read INTEGER DEFAULT 0,
                hash TEXT,
                FOREIGN KEY (sender_id) REFERENCES app_users(user_id),
                FOREIGN KEY (receiver_id) REFERENCES app_users(user_id)
            );

            CREATE TABLE IF NOT EXISTS attachments(
                attachment_id INTEGER PRIMARY KEY,
                message_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                key TEXT NOT NULL,
                hash TEXT,
                FOREIGN KEY (message_id) REFERENCES messages(message_id)
            );
            """

            cursor.executescript(setup_command)

    except sqlite3.OperationalError as e:
        print('Failed to conenct to databse:', e)

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = dict_factory 

    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()