from Crypto.Cipher import AES
import scrypt, os, binascii, getpass

def encrypt_AES_GCM(msg, password):
    kdfSalt = os.urandom(16)
    secretKey = scrypt.hash(password, kdfSalt, N=16384, r=8, p=1, buflen=32)
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (kdfSalt, ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, password):
    (kdfSalt, ciphertext, nonce, authTag) = encryptedMsg
    secretKey = scrypt.hash(password, kdfSalt, N=16384, r=8, p=1, buflen=32)
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def read_hex(prompt):
    return binascii.unhexlify(input(prompt).strip())


purpose = input("Do you want to encrypt (enter 1), or decrypt (enter 0):")
purpose = int(purpose)

# fileName = input("Enter file name to be encrypted:")
# fileHandle = open(fileName, 'r')
# msg = b'Message for AES-256-GCM + Scrypt encryption'
if purpose:
    msg = input("Enter message:")
    msg = msg.encode("utf-8")
    password = getpass.getpass("Enter password:")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        
    else:
        print("Password confirmed.")

        print("")
        print("------------------------------")
        print("Encrypting message......")
        print("")

        salt, ciphertext, nonce, tag = encrypt_AES_GCM(msg, password.encode("utf-8"))
        print("kdfSalt:   ", binascii.hexlify(salt).decode())
        print("ciphertext:", binascii.hexlify(ciphertext).decode())
        print("aesIV:     ", binascii.hexlify(nonce).decode())
        print("authTag:   ", binascii.hexlify(tag).decode())
else:
    print("Enter the encrypted message piece by piece:")
    

    encryptedMsg = (
        read_hex("Enter the salt (hex): "),
        read_hex("Enter the ciphertext (hex): "),
        read_hex("Enter the IV (hex): "),
        read_hex("Enter the authTag (hex): "),
    )

    password = getpass.getpass("Enter password:")
    try:
        plaintext = decrypt_AES_GCM(encryptedMsg, password.encode("utf-8"))
        print("decryptedMsg:", plaintext.decode("utf-8"))
    except ValueError:
        print("Decryption failed: wrong password or altered data.")




# You may need to activate the virtual environment before running this script
# Please run the following command
# `source ~/venvs/crypto-env/bin/activate`