from http import HTTPStatus

from DbController import get_db
import DTOs
import time
from http import HTTPStatus

class MessageService():
    def get_key_by_login(self, login: str):
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "SELECT public_key FROM app_users WHERE login = ?",
                (login,)
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
                "SELECT user_id FROM app_users where login = ?", (receiver_name,)
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
        
message_service = MessageService()