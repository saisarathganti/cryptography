from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import os
import hmac

def verification(msg):
    secret = bytes('dude', 'utf-8')
    msg = msg.encode()
    return hmac.new(secret, msg, hashlib.sha512).hexdigest()
 
def encryption(msg, key):
    salt = os.urandom(16)
    crypt = AES.new(key, AES.MODE_CBC,salt)
    return salt, crypt.encrypt(msg)
 
def decryption(salt, encrypted_message, key):
    crypt = AES.new(key, AES.MODE_CBC,salt)
    return crypt.decrypt(encrypted_message)
 
def send_message(message):
    password = "-Ju&R>m$8_CJ7JJC"
    salt, encrypted_message = encryption(message*16, password)
    hmac_message = verification(message)
    decrypted_message = decryption(salt, encrypted_message, password)
    decrypted_message = decrypted_message.decode("utf-8")
    decrypted_message = decrypted_message[0:len(message)]
    if not verification(decrypted_message) == hmac_message:
        return "Message is Corrupted"
    return decrypted_message

try:
    while True:
        message = input("Enter message : ")
        received_message = send_message(message)
        print("Message received:\n", received_message)
except KeyboardInterrupt:
    pass