from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import Crypto.Signature.pkcs1_15 as pkcs1_15
import Crypto.Hash.SHA256 as SHA256
from password_validator import PasswordValidator
from email_validator import validate_email, EmailNotValidError
import stat
import bcrypt
import base64
import getpass
import json
import os
import gc
import socket
import threading
import time

# CODE FOR  ENCRYPTION
def generate_key_pair():
  key = RSA.generate(2048)
  private_key = key.export_key()
  public_key = key.publickey().export_key()
  return private_key, public_key

def encrypt_data(aes_key, data):
  cipher = AES.new(aes_key, AES.MODE_EAX)
  ciphertext, tag = cipher.encrypt_and_digest(data.encode())
  return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_data(aes_key, encrypted_data):
  encrypted_data = base64.b64decode(encrypted_data)
  nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
  cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
  data = cipher.decrypt_and_verify(ciphertext, tag)
  return data.decode()

def sign_data(private_key, data):
  key = RSA.import_key(private_key)
  print(f"{base64.b64decode(data)}")
  h = SHA256.new(base64.b64decode(data))
  signature = pkcs1_15.new(key).sign(h)
  return base64.b64encode(signature).decode()

def encrypt_asymmetric(public_key, data):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_data = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_asymmetric(private_key, encrypted_data):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    decrypted_data_bytes = cipher.decrypt(encrypted_data_bytes)
    decrypted_data = decrypted_data_bytes.decode('utf-8')
    return decrypted_data

def encrypt_file(aes_key, file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = AES.new(base64.b64decode(aes_key), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_file(aes_key, encrypted_data, output_path):
    encrypted_data = base64.b64decode(encrypted_data)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(output_path, 'wb') as f:
        f.write(data)

def calculate_file_hash(file_path):
    sha256_hash = SHA256.new()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def send_file(aes_key, file_path, recipient_ip, recipient_key, account_info, recipient_port=25256):
    encrypted_data = encrypt_file(aes_key, file_path) + ";"
    file_hash = calculate_file_hash(file_path) + ";"
    print(f"{aes_key}")
    
    encrypted_aes = encrypt_asymmetric(recipient_key, aes_key) + ";"
    print(f"{encrypted_aes}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((recipient_ip, recipient_port))
        # Send sender's information
        sender_name = account_info["name"]
        sender_email = account_info["email"]
        sender_info = f"{sender_name};{sender_email};"
        s.sendall(sender_info.encode())
        
        # Send the encrypted data and hash
        s.sendall(encrypted_data.encode())
        s.sendall(file_hash.encode())
        s.sendall(encrypted_aes.encode())
        s.close()

def receive_file(aes_key, account_info, save_path, listen_ip, listen_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((listen_ip, listen_port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            # Receive sender's information
            sender_info = conn.recv(1024 * 100).decode()
            sender_name, sender_email, encrypted_data, received_hash, encrypted_aes, other_data = sender_info.split(';')
            print(f"Contact '{sender_name} <{sender_email}>' is sending a file. Accept (y/n)?")
            response = input().lower()
            if response != 'y':
                print("File transfer declined.")
                return
            private_key = account_info.get("private_key")
            # Receive the encrypted data and hash
            decrypted_aes = decrypt_asymmetric(private_key, encrypted_aes)
            
            # Decrypt the file and verify its integrity
            decrypt_file(base64.b64decode(decrypted_aes), encrypted_data, save_path)
            file_hash = calculate_file_hash(save_path)
            if file_hash == received_hash:
                print("File transfer successful and integrity verified.")
            else:
                print("File transfer failed. Integrity check failed.")

def start_file_listener(aes_key, account_info, save_path, listen_ip, listen_port):
    listener_thread = threading.Thread(target=receive_file, args=(aes_key, account_info, save_path, listen_ip, listen_port))
    listener_thread.daemon = True
    listener_thread.start()

#REGISTRATION CODE
def user_reg():
    schema = PasswordValidator()
    schema\
    .min(8)\
    .max(100)\
    .has().uppercase()\
    .has().lowercase()\
    .has().digits()\
    .has().no().spaces()

    try:
        name = input("Enter Full Name: ")

        # Email validation with try-except for better error handling
        while True:
            email = input("Enter Email Address: ")
            try:
                validate_email(email, check_deliverability=True)
                break  # Break the loop if the email is valid
            except EmailNotValidError:
                print("Enter a valid email address")

        while True:
            password = getpass.getpass("Enter your password: ")
            RePassword = getpass.getpass("Re-enter your password: ")

            # Check password validity using the validator schema
            if not schema.validate(password):
                print("Please enter a password of 8 characters containing letters, numbers, and uppercase and lowercase letters")
            elif password == '':
                print("Password cannot be empty. Please try again.")
            elif password != RePassword:
                print("Passwords do not match. Please try again.")
            else:
                print("\nPasswords Match.\nUser Registered.\nExiting SecureDrop...")

                # Password hashing
                salt = bcrypt.gensalt()  # bcrypt
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

                # Generate keys
                private_key, public_key = generate_key_pair()
                aes_key = get_random_bytes(32)

                # Account information to be saved
                account_info = {
                    "name": name,
                    "email": email,
                    "password": hashed_password.decode('utf-8'),
                    "private_key": private_key.decode('utf-8'),
                    "public_key": public_key.decode('utf-8'),
                    "aes_key": base64.b64encode(aes_key).decode('utf-8'),
                    "contacts": {}
                }

                try:
                    with open("accounts.json", "w") as file:
                        json.dump(account_info, file, indent=4)
                    os.chmod("accounts.json", stat.S_IRUSR | stat.S_IWUSR)
                except Exception as e:
                    print(f"Error occurred while writing the file: {e}")
                    exit()
                break

    except KeyboardInterrupt:
        print('\nKeyboard Interrupt. Exiting SecureDrop...')
        exit()
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        exit()
    finally:
        if 'name' in locals():
            del name
        if 'email' in locals():
            del email
        if 'password' in locals():
            del password
        if 'RePassword' in locals():
            del RePassword
        if 'account_info' in locals():
            del account_info
        gc.collect()


#LOGIN CODE
def user_login():
  try:
    while True:
      with open("accounts.json", "r") as file:
        account_info = json.load(file)

        email = input("Enter your email: ")
        password = getpass.getpass("Enter your password: ")

        if email == account_info["email"] and bcrypt.checkpw(password.encode('utf-8'), account_info["password"].encode('utf-8')):
          print("Welcome to SecureDrop.\nType 'help' for commands.\n")
          secure_drop_shell(account_info)
          break
        else:
          print("Email and Password Combination Invalid.\n")
          email = ''
          password = ''
  except:
    print('\nKeyboard Interrupt. Exiting SecureDrop...')
    exit()
  finally:
    if 'email' in locals():
      del email
    if 'password' in locals():
      del password
    if 'account_info' in locals():
      del account_info
    gc.collect()






#APPLICATION CODE
def secure_drop_shell(account_info):
    try:
        # Start the file listener thread
        save_path = "./file.png"  # Change this to your desired save path
        listen_ip = "0.0.0.0"  # Listen on all interfaces
        listen_port = 25256 + 1  # Port for listening
        aes_key = account_info["aes_key"]
        print("test 1")
        start_file_listener(aes_key, account_info, save_path, listen_ip, listen_port)
        
        while True:
            command = input("secure_drop> ").lower()
            if command in ["help"]:
                print("add -> Add a new contact")
                print("list -> List all online contacts")
                print("send -> Transfer file to contact")
                print("exit -> Exit SecureDrop")
            elif command in ["exit"]:
                print("Exiting SecureDrop...")
                break
            elif command in ["add"]:
                find_user(account_info)
            elif command.startswith("send "):
                parts = command.split()
                if len(parts) != 3:
                    print("Usage: send <email> <file_path>")
                    continue
                recipient_email = parts[1]
                file_path = parts[2]
                print(f"{file_path}")
                
                # Check if the recipient is in the contacts list
                if recipient_email not in account_info.get("contacts"):
                    print(f"Contact {recipient_email} not found in contacts list.")
                    continue

                # Get recipient IP from contacts list
                recipient_ip = get_contact_ip(recipient_email)
                recipient_key = get_contact_key(recipient_email)
                if not recipient_ip:
                    print(f"Could not find IP address for {recipient_email}.")
                    continue
                
                # Send the file
                print(f"{aes_key}")
                send_file(aes_key, file_path, recipient_ip, recipient_key, account_info)
                
                print("Contact has accepted the transfer request.")
                print("File has been successfully transferred.")
            else:
                print(f"Unknown command: {command}")
    except KeyboardInterrupt:
        exit()
    finally:
        del account_info
        gc.collect()

def get_contact_ip(email, filename="accounts.json"):
    """Retrieve the IP address of a contact from the contacts file."""
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            account_info = json.load(file)
            contacts = account_info.get("contacts", {})
            data = contacts.get(email, {})
            return data.get("IP")
    return None

def get_contact_key(email, filename="accounts.json"):
    """Retrieve the IP address of a contact from the contacts file."""
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            account_info = json.load(file)
            contacts = account_info.get("contacts", {})
            data = contacts.get(email, {})
            return data.get("public_key")
    return None

def load_username(filename="accounts.json"):
    """Loads the current user's username (email) from the accounts file."""
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as file:
                account_info = json.load(file)
                email = account_info.get("email", None)
                public_key = account_info.get("public_key", None)
                return email, public_key  # Return the email if it exists
        else:
            print("No accounts file found.")
            return None
    except Exception as e:
        print(f"Error while loading username: {e}")
        return None
      

def find_user(account_info):
    """Automatically finds users broadcasting their presence and adds them as contacts."""
    username, public_key = load_username()
    if not username:
      print("Username not found. Exiting.")
      return
      
    try:
        while True:
            send_email = input("Enter the email for who you are looking for: ")

            if validate_email(send_email):
              print("Email validated")
              break
            else:
              print("Email invalid, please type a valid email to search for")
    except KeyboardInterrupt:
        print('\nKeyboard Interrupt. Exiting SecureDrop...')
        return
    except Exception as e:
        print(f"An error occurred: {e}")

    
   
    

    def broadcast_and_listen():
        """Handles both sending and listening for broadcasts."""
        broadcast_ip = '255.255.255.255'  # Broadcast address
        port = 25256  # Port for broadcasting
        local_ip = get_local_ip()
        message = f"SecureDrop_Email:{send_email};Sender_Email:{username};IP:{local_ip};public_key:{public_key}"

        # Create UDP socket for sending and listening
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', port + 1))  # Bind to listen on the same port

        contacts = set()

        try:
            print(f"Broadcasting presence looking for {send_email} as {username} and listening for responses...")

            # Send broadcast message periodically
            threading.Thread(target=periodic_broadcast, args=(sock, message, broadcast_ip, port), daemon=True).start()

            while True:
                # Listen for incoming broadcasts
                data, addr = sock.recvfrom(1024)  # Receive data (up to 1024 bytes)
                message = data.decode()
               # print(f"Received message: {data.decode()} from {addr}") # # uncomment to display all udp packets recieved

                if message.startswith("SecureDrop_Email:"):
                    # Parse the incoming broadcast
                    parts = message.split(';')
                    user_data = {part.split(':')[0]: part.split(':')[1] for part in parts}
                    received_username = user_data.get("Sender_Email") #ech@ech.com
                    sender_ip = user_data.get("IP") # comp2
                    sender_key = user_data.get("public_key")
                    
                    
                    print(received_username) # 
                    print(sender_ip) # comp 2 ip[]
                    print(send_email) 
                    if received_username == send_email and received_username != username:
                        print(f"Found user {received_username} broadcasting from {sender_ip}")
                        contacts.add(received_username)
                        update_contacts(username, received_username, sender_ip, sender_key)
                        print(f"Added {received_username} to contacts.")
        except KeyboardInterrupt:
            print("Stopping broadcast listener...")
        finally:
            sock.close()

    def periodic_broadcast(sock, message, broadcast_ip, port):
        """Sends broadcast messages periodically."""
        while True:
            sock.sendto(message.encode(), (broadcast_ip, port))
            time.sleep(5)  # Broadcast every 5 seconds

    # Start broadcast and listening operations
    broadcast_and_listen()

def update_contacts(username, new_contact, new_ip, new_key, filename="accounts.json"):
    """Updates the contacts list in the accounts file."""
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            data = json.load(file)

        # Initialize contacts list if it doesn't exist
        if "contacts" not in data:
            data["contacts"] = {}

        # Avoid duplicates
        if new_contact not in data["contacts"]:
            data["contacts"][new_contact] = {}
            data["contacts"][new_contact]["IP"] = new_ip
            data["contacts"][new_contact]["public_key"] = new_key
            print(f"Contact {new_contact} added successfully.")
        else:
            print(f"Contact {new_contact} is already in the contacts list.")

        # Save the updated data into the JSON file
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
    else:
        print("No accounts file found!")

def get_local_ip(broadcast_ip='255.255.255.255', port=25256):
    """Gets the local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect((broadcast_ip, port))
        local_ip = s.getsockname()[0]
    except:
        local_ip = '127.0.0.1'  # Fallback to loopback if no network is available
    finally:
        s.close()
    return local_ip



#STARTUP CODE
def main():
    MAX_ATTEMPTS = 3

    if not os.path.exists("accounts.json"):
        while True:
            print('No users are registered with this client.\nDo you want to register a new user? (y/n): ', end='')
            try:
                response = input().lower()
            except KeyboardInterrupt:
                print('\nKeyboard Interrupt. Exiting SecureDrop...')
                exit()
            if response.startswith('y'):
                user_reg()
                break
            elif response.startswith('n'):
                print('Exiting SecureDrop...')
                exit()
            else:
                print('Invalid input. Try again\n')
                response = ''
    else:
        attempts = 0
        while attempts < MAX_ATTEMPTS:
            username = input("Enter Email: ")
            password = getpass.getpass("Enter Password: ")

            try:
                with open("accounts.json", "r") as file:
                    account_info = json.load(file)

                if "email" not in account_info or "password" not in account_info:
                    print("Invalid account data format. Please contact support.")
                    exit()

                if username == account_info["email"] and bcrypt.checkpw(password.encode('utf-8'), account_info["password"].encode('utf-8')):
                    print("Login successful!")
                    secure_drop_shell(account_info)
                    break
                else:
                    print("Invalid email or password.\n")
                    attempts += 1
                    print(f"{MAX_ATTEMPTS - attempts} attempts remaining.")

            except json.JSONDecodeError:
                print("Error: Could not decode accounts file. Please check the file format.")
                exit()
            except FileNotFoundError:
                print("Error: Accounts file is missing.")
                exit()
            except Exception as e:
                print(f"Unexpected error occurred: {e}")
                attempts += 1
                if attempts == MAX_ATTEMPTS:
                    print("Exiting SecureDrop due to too many failed login attempts.")
                    exit()

        if attempts == MAX_ATTEMPTS:
            print("Too many failed attempts. Exiting SecureDrop...")
            exit()

if __name__ == '__main__':
    main()

def verify_signature(public_key, data, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False
