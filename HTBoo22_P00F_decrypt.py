from Crypto.Cipher import AES
import os

def decrypt_file(filename: str, output_filename: str) -> None:
    # Read the encrypted data
    encrypted_data = open(filename, 'rb').read()

    # Key and IV used in the encryption process
    key = 'vN0nb7ZshjAWiCzv'
    iv = b'ffTC776Wt59Qawe1'

    # Set up the AES cipher for decryption
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Write the decrypted data to a new file
    with open(output_filename, 'wb') as f:
        f.write(decrypted_data)

# Example usage
decrypt_file('candy_dungeon.pdf.boo', 'candy_dungeon.pdf')
print("Decryption complete! The decrypted file is saved as 'candy_dungeon.pdf'.")
