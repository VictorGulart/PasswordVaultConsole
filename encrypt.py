# import qrcode
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from base64 import urlsafe_b64encode
from os import urandom
from hashlib import scrypt

# Exception handling
from cryptography.fernet import InvalidToken

class Encrypt:
    '''
        Major class that has all the encryption functionality
        interactive login: N=16384, r=8, p=1 (RAM = 2 MB).
        file encryption: N=1048576, r=8, p=1 (RAM = 1 GB)
    '''
    @staticmethod
    def gen_qr_code():
        ...
    
    @staticmethod
    def encrypt(data, key):
        '''
            Encrypts data with a key
            data must be bytes
            Return the token
        '''
        f = Fernet(key)
        token = f.encrypt(data)
        return token
      
    @staticmethod
    def decrypt(token, key):
        '''
            Decrypts a token with a key
            Returns the data
        '''
        f = Fernet(key)
        data = f.decrypt(token)
        return data
    
    @staticmethod
    def encrypt_file(filename, key):
        '''
            Encrypts a file with a key
            Saves the token on the file
        '''
        data = None
        with open(filename, 'rb') as file:
            data = file.read() 
        
        with open(filename, 'wb') as file:
            token = Encrypt.encrypt(data, key)
            file.write(token)
     
    @staticmethod
    def decrypt_file(filename, key):
        '''
            Decrypts a file with a key
            Write the data back to the file
        '''
        token = None
        data = None

        with open(filename, 'rb') as file:
            # Read the token from the file
            token = file.read()
        
        data = Encrypt.decrypt(token, key)
            
        with open(filename, 'wb') as file:
            # Decrypt the token and write it back

            file.write(data)

    @staticmethod
    def gen_random_key():
        '''
            Generates a random key with Fernet
            -> change for Scrypt
        '''
        return Fernet.generate_key() 

    @staticmethod
    def gen_pass_key(password):
        '''
            Generates a Scrypt key encoded with base64
            returns the key with the salt used
        '''
        salt = Encrypt.get_random_salt()
        kdf = Scrypt(salt, 32, n=16384, r=8, p=1)
        key = urlsafe_b64encode(kdf.derive(password.encode()))
        return [key, salt]

    @staticmethod
    def get_random_salt():
        '''
            Generates a random salt
        '''
        return  urlsafe_b64encode( urandom(16) )
    
    @staticmethod
    def get_hash(password, salt):
        '''
            Hashes a password with a salt encoded with base64
            using hashlib module, with algo scrypt
            default derived key length is 16
            salt is already encoded, it comes from the database
        '''
        hashed = scrypt(password.encode(), salt=salt, dklen=32, n=16384, r=8, p=1)
        hashed = urlsafe_b64encode(hashed)
        return hashed

if __name__ == "__main__":
    key, salt = Encrypt.gen_pass_key("narutokunandhinata")

    data = "this is the data".encode()

    print("creating token")
    token = Encrypt.encrypt(data, key)

    # right key 
    print("getting data back")
    data = Encrypt.decrypt(token, key) # this should through an error
    print("data ", data)

