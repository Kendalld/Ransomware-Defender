# Trevor Schwarz, EEP 595 Project, Fall2024
# Modified from Decoder.py in RansomwareSim/HalilDeniz
import gc
import socket
import json
import os
from cryptography.fernet import Fernet

class Decoder:
    def __init__(self, directory):
        self.directory = directory

    def decrypt_file(self, file_path, key):
        fernet = Fernet(key)
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)

        original_file_path = file_path.replace(".hakd", "")
        with open(original_file_path, 'wb') as file:
            file.write(decrypted_data)

        os.remove(file_path)

    def find_and_decrypt_files(self, key):
        for root, _, files in os.walk(self.directory):
            for file in files:
                if file.endswith(".hakd"):
                    file_path = os.path.join(root, file)
                    self.decrypt_file(file_path, key)

    def clear_memory(self):
        gc.collect()
        print("Memory cleared.")

def DecoderFunc(keyString, targetDir):
    #directory = 'rw_target/'  # Replace with the target directory path
    print('\n*** Decoder launched ***')
    
    inputAccepted = False
    decodeFlag = False
    while not inputAccepted:
        try:
            print("Decrypt files in %s using key %s?" % (targetDir, keyString))
            capture = input("Enter Y/N")
            if(capture.lower()=='y'):
                inputAccepted = True
                decodeFlag = True
            elif (capture.lower()=='n'):
                inputAccepted = True
                print('Decryption not attempted...')
            else:
                print('Invalid input')
        except Exception as e:
            print(f"An error occurred: {e}\n Check your input")

    if(decodeFlag):
        try:
            decoder = Decoder(targetDir)
            key = keyString

            if key:
                decoder.find_and_decrypt_files(key)
                print("Files successfully decrypted.")
            else:
                print("Key not found or incorrect.")
        except Exception as e:
            print(f"An error occurred: {e}\nPlease restart the program.")

        decoder.clear_memory()
    
    
