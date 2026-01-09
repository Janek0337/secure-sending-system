import time
import os
import io
import secrets
from shared.Ciphrer import ciphrer
import base64
from Crypto.Hash import HMAC, SHA256
from math import floor
from urllib.parse import quote
import qrcode

class TOTP_manager:
    def __init__(self):
        self.env_name = None

    def get_master_key(self):
        master_key = os.getenv('MASTER_KEY')
        if master_key is None:
            raise RuntimeError("Could not get MASTER KEY from environment. Ensure server/.env is loaded.")
        return master_key

    def generate_secret(self):
        return base64.b32encode(secrets.token_bytes(20)).decode('utf-8')

    def encrypt_secret(self, secret: str):
        master_key = self.get_master_key()
        encrypted_bytes, _ = ciphrer.encrypt_data(secret.encode("utf-8"), base64.b64decode(master_key))
        return base64.b64encode(encrypted_bytes).decode("utf-8")

    def decrypt_secret(self, encrypted: str):
        master_key = self.get_master_key()
        decoded_encrypted_bytes = base64.b64decode(encrypted)
        decrypted_bytes = ciphrer.decrypt_data(decoded_encrypted_bytes, base64.b64decode(master_key))
        return decrypted_bytes.decode("utf-8")

    def generate_qr_code(self, secret_base32, username):
        issuer="Secure Sending System"
        label = f"{issuer}:{username}"

        uri = (
            f"otpauth://totp/{quote(label)}?"
            f"secret={secret_base32}&"
            f"issuer={quote(issuer)}&"
            f"algorithm=SHA256&"
            f"digits=6&"
            f"period=30"
        )
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode("utf-8")


    # also allows for a next time window's code
    def count_totp_code(self, secret) -> list[str]:
        time_window_s = 30
        valid_codes = []
        K = base64.b32decode(secret, casefold=True)
        for shift in (0, time_window_s):
            T = floor((time.time() + shift) /time_window_s)
            C = T.to_bytes(8, byteorder='big')

            h = HMAC.new(K, msg=C, digestmod=SHA256)
            hmac_result = h.digest()

            offset = hmac_result[-1] & 0x0F
            four_bytes_for_number = hmac_result[offset:offset + 4]
            full_num = int.from_bytes(four_bytes_for_number, byteorder='big')
            the_number = full_num & 0x7FFFFFFF
            code = the_number % 10**6
            valid_codes.append(f"{code:06d}")

        return valid_codes

totp_manager = TOTP_manager()
