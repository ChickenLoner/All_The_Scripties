CIPHER = "Tr3v0rC2R0x@nd1s@w350m3#TrevorForget"

# Credit to Abdelrhman

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """
    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


# Initialize the cipher
encrypted_cipher = AESCipher(CIPHER)

# Loop for user input
print("Enter encrypted texts to decrypt (type 'exit' to quit):")
while True:
    user_input = input("Encrypted Text: ").strip()
    if user_input.lower() == "exit":
        print("Exiting...")
        break
    try:
        decrypted_text = encrypted_cipher.decrypt(user_input)
        print(f"Decrypted Text: {decrypted_text}")
    except Exception as e:
        print(f"Error decrypting text: {e}")
