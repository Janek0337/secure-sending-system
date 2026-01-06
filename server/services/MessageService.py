from server.DbController import get_db
from shared import DTOs
import time
import traceback
from pydantic import ValidationError

class MessageService:
    def get_key_by_username(self, usernames: DTOs.KeyTransferDTO):
        if not usernames:
            return {}
        try:
            db = get_db()
            cursor = db.cursor()
            placeholders = ', '.join(['?'] * len(usernames.key_list))
            query = f"SELECT username, public_key FROM app_users WHERE username IN ({placeholders})"
            cursor.execute(query, list(usernames.key_list.keys()))
            result = cursor.fetchall()
            if result is not None:
                return {res['username'] : res['public_key'] for res in result}
            return {}
        except Exception as e:
            error_details = traceback.format_exc()
            print("Wystąpił błąd:\n", error_details)
            return {}

    def save_message(self, sender_uid: int, valid_messages: list[DTOs.MessageDTO]):
        db = get_db()
        result_dict = {}
        try:
            cursor = db.cursor()
            for valid_message in valid_messages:
                receiver_name = valid_message.receiver
                cursor.execute(
                    "SELECT user_id FROM app_users where username = ?", (receiver_name,)
                )
                result = cursor.fetchone()
                if result is None:
                    result_dict[receiver_name] = False
                    continue
                receiver_uid = result['user_id']

                cursor.execute(
                    "INSERT INTO messages (content, key, sender_id, receiver_id, date_sent, hash) VALUES (?, ?, ?, ?, ?, ?)",
                    (valid_message.content[0], valid_message.content[1], sender_uid, receiver_uid, time.time(), valid_message.content[2])
                )
                message_id = cursor.lastrowid
                attachments_data = [(message_id, a[0][0], a[0][1], a[1], a[2]) for a in valid_message.attachments]
                cursor.executemany(
                    "INSERT INTO attachments (message_id, name, content, key, hash) VALUES (?, ?, ?, ?, ?)",
                    attachments_data
                )
                result_dict[receiver_name] = True
            db.commit()
            return result_dict
        except Exception as e:
            print("Database error:", e)
            return None

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

    def get_the_message(self, receiver_username: str, message_id: int):
        if not self.is_user_receiver_of_message(receiver_username, message_id):
            return False

        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "SELECT m.date_sent, m.is_read, "
                "m.message_id, m.key, m.content, a.username, m.hash "
                "FROM messages m "
                "JOIN app_users a on m.sender_id = a.user_id "
                "WHERE m.message_id = ? ",
                (message_id,)
            )

            message_results = cursor.fetchone()

            cursor.execute(
                "SELECT name, content, key, hash "
                "FROM attachments "
                "WHERE message_id = ?",
                (message_id,)
            )

            attachment_results = cursor.fetchall()

            dto = DTOs.GetMessageDTO(
                sender = message_results['username'],
                content = (message_results['content'], message_results['key'], message_results['hash']),
                attachments = [((a['name'], a['content']), a['key'], a['hash']) for a in attachment_results],
                date_sent = message_results['date_sent']
            )
            return dto
        except Exception as e:
            print("Database error here:", e)
            return False

    def is_user_receiver_of_message(self, username: str, message_id: int) -> bool:
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "SELECT u.username "
                "FROM messages m "
                "JOIN app_users u ON m.receiver_id = u.user_id "
                "WHERE m.message_id = ?", (message_id,)
            )
            result = cursor.fetchone()
            return result is not None and result['username'] == username
        except Exception as e:
            print("Database error:", e)
            return False

    def mark_read(self, message_id: int):
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "UPDATE messages "
                "SET is_read = 1 "
                "WHERE message_id = ?", (message_id,)
            )
            db.commit()
            return True
        except Exception as e:
            print("Database error:", e)
            return False

    def delete_message(self, message_id):
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                "DELETE FROM messages WHERE message_id = ?", (message_id,)
            )
            cursor.execute(
                "DELETE FROM attachments WHERE message_id = ?", (message_id,)
            )
            db.commit()
            return True
        except Exception as e:
            print("Database error:", e)
            return False
        
message_service = MessageService()