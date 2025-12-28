from http import HTTPStatus

from DbController import get_db
import DTOs
import time
from http import HTTPStatus

from pydantic import ValidationError


class MessageService():
    def get_key_by_username(self, username: str):
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "SELECT public_key FROM app_users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            if result is not None:
                return result['public_key']
            return None
        except Exception as e:
            print("Database error:", e)
            return None

    def save_message(self, sender_uid: int, receiver_name: str, valid_message: DTOs.MessageDTO):
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "SELECT user_id FROM app_users where username = ?", (receiver_name,)
            )
            result = cursor.fetchone()
            if result is None:
                return HTTPStatus.NOT_FOUND
            receiver_uid = result['user_id']

            cursor.execute(
                "INSERT INTO messages (content, key, sender_id, receiver_id, date_sent) VALUES (?, ?, ?, ?, ?)",
                (valid_message.content[0], valid_message.content[1], sender_uid, receiver_uid, time.time())
            )
            message_id = cursor.lastrowid
            attachments_data = [(message_id, a[0][0], a[0][1], a[1]) for a in valid_message.attachments]
            cursor.executemany(
                "INSERT INTO attachments (message_id, name, content, key) VALUES (?, ?, ?, ?)",
                attachments_data
            )
            db.commit()
            return HTTPStatus.CREATED
        except Exception as e:
            print("Database error:", e)
            return HTTPStatus.INTERNAL_SERVER_ERROR

    def get_messages_list(self, receiver_uid: int):
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "SELECT datetime(m.date_sent, 'unixepoch', 'localtime') AS date_sent, a.username, m.is_read, m.message_id "
                "FROM messages m "
                "JOIN app_users a on m.sender_id = a.user_id "
                "WHERE m.receiver_id = ? "
                "ORDER BY m.date_sent DESC",
                (receiver_uid,)
            )

            messages = cursor.fetchall()
            try:
                return [DTOs.MessageListElementDTO(**m) for m in messages]
            except ValidationError:
                return []
        except Exception as e:
            print("Database error:", e)
            return []
        
message_service = MessageService()