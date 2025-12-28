from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class KeyManager():
    def __init__(self):
        self.key: RSA.RsaKey = None

    def get_priv_key_text(self, password):
        if self.key is None:
            return None
        return self.key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC").decode("utf-8")

    def get_pub_key_text(self):
        if self.key is None:
            return None
        pub_key_obj = self.key.publickey()
        return pub_key_obj.export_key(format='PEM').decode("utf-8")

    def get_key_from_text(self, key: str):
        try:
            key = RSA.import_key(key)
            self.key = key
        except ValueError:
            print("Invalid key")
            return None

    def create_key(self):
        self.key = RSA.generate(2048)

    def save_key(self, username, password):
        if self.key is None:
            self.load_key(username)
            if self.key is None:
                return False
        private_pem = self.get_priv_key_text(password)
        with open(f"keys/private_key_{username}.pem", "wb") as f:
            f.write(private_pem.encode("utf-8"))

        return True

    def load_key(self, username):
        with open(f"keys/private_key_{username}.pem", "rb") as f:
            key_data = f.read()
        self.key = RSA.import_key(key_data)

        return True

    def encrypt_data(self, data: bytes, pub_key: str) -> bytes:
        public_key = RSA.import_key(pub_key)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(data)

        return encrypted
    
    def decrypt_data(self, encrypted_data: bytes, priv_key: str) -> bytes:
        private_key = RSA.import_key(priv_key)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(encrypted_data)

        return decrypted