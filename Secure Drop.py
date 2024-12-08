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
  h = SHA256.new(data.encode())
  signature = pkcs1_15.new(key).sign(h)
  return base64.b64encode(signature).decode()

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
                aes_key = get_random_bytes(16)

                # Account information to be saved
                account_info = {
                    "name": name,
                    "email": email,
                    "password": hashed_password.decode('utf-8'),
                    "private_key": private_key.decode('utf-8'),
                    "public_key": public_key.decode('utf-8'),
                    "aes_key": base64.b64encode(aes_key).decode('utf-8'),
                    "contacts": []
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
    while True:
      command = input("secure_drop> ").lower()
      if command in ["help"]:
        print("add -> Add a new contact")
        print("exit -> Exit SecureDrop")
      elif command in ["exit"]:
        print("Exiting SecureDrop...")
        break
      elif command in ["add"]:
        add_contact(account_info)
      else:
        print(f"Unknown command: {command}")
  except KeyboardInterrupt:
    exit()
  finally:
      del account_info
      gc.collect()

def add_contact(account_info):
  #find_user() should replace all of this
  try:
    name = input("Enter Full Name: ")
    email = input("Enter Email Address: ")

    contact = {
        "name": name,
        "email": email
    }

    aes_key = base64.b64decode(account_info["aes_key"])
    encrypted_contact = {
        "name": encrypt_data(aes_key, name),
        "email": encrypt_data(aes_key, email)
    }

    private_key = account_info["private_key"].encode('utf-8')
    signature = sign_data(private_key, json.dumps(encrypted_contact))

    account_info["contacts"].append({"contact": encrypted_contact, "signature": signature})

    with open("accounts.json", "w") as file:
      json.dump(account_info, file, indent=4)
  except KeyboardInterrupt:
    exit()
  finally:
    if 'name' in locals():
      del name
    if 'email' in locals():
      del email
    if 'contact' in locals():
      del contact
    if 'aes_key' in locals():
      del aes_key
    if 'encrypted_contact' in locals():
      del encrypted_contact
    if 'private_key' in locals():
      del private_key
    if 'signature' in locals():
      del signature
    gc.collect()




#UDP Connection
def load_username(filename="accounts.json"):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            data = json.load(file)
            return data.get("email")  # Fetch the username from the JSON
    else:
        print("No accounts file found!")
        return None

def update_contacts(username, new_contact, filename="accounts.json"):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            data = json.load(file)
        
        # Initialize the contacts list
        if "contacts" not in data:
            data["contacts"] = []

        # Avoid duplicates
        if new_contact not in data["contacts"]:
            data["contacts"].append(new_contact)
            print(f"Contact {new_contact} added successfully.")
        else:
            print(f"Contact {new_contact} is already in the contacts list.")
        
        # Save the updated data into JSON File
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
    else:
        print("No accounts file found!")

def find_user():
    username = load_username()

    if not username:
        print("Username not found. Exiting.")
        return

    # Start threads for sending and listening for UDP broadcasts
    send_thread = threading.Thread(target=send_broadcast)
    listen_thread = threading.Thread(target=listen_for_broadcasts)

    send_thread.start()  # Send the broadcast
    listen_thread.start()  # Listen for incoming broadcasts

    send_thread.join()  # Wait for send thread to finish (or forever)
    listen_thread.join()  # Wait for listen thread to finish (or forever)

def get_local_ip(broadcast_ip='10.254.254.254', port=12345):
    # Get the local machine's IP address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect((broadcast_ip, port))  # Connect to an external address
        local_ip = s.getsockname()[0]    # Get the local IP address
    except:
        local_ip = '127.0.0.1'  # Fallback to loopback address if no network is available
    finally:
        s.close()
    return local_ip

def send_broadcast():
    # Send a UDP broadcast message with the local IP
    broadcast_ip = '<broadcast>'  # Broadcast address
    port = 12345  # Choose a port for broadcasting
    target_username = input("Enter the username you're looking for: ")
    local_ip = get_local_ip()
    username = load_username()

    message = f"SecureDrop_User:{username};Target:{target_username};IP:{local_ip}"

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        sock.sendto(message.encode(), (broadcast_ip, port))  # Send the broadcast message
        print(f"Broadcasting as {username} looking for {target_username}")
    finally:
        sock.close()

def listen_for_broadcasts(username):
    # Listen for UDP broadcast responses from other machines
    port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))  # Bind to all IPs on the specified port

    try:
        print(f"Listening for broadcasts on port {port}...")
        contacts = set()

        while True:
            data, addr = sock.recvfrom(1024)  # Receive data (up to 1024 bytes)
            message = data.decode()
            if message.startswith("SecureDrop_User:"):
                # Parse incoming broadcast
                parts = message.split(';')
                user_data = {part.split(':')[0]: part.split(':')[1] for part in parts}
                received_username = user_data.get("SecureDrop_User")
                target_username = user_data.get("Target")
                sender_ip = user_data.get("IP")
                
                if received_username == username and target_username:
                    print(f"User {target_username} is looking for you!")
                    contacts.add(target_username)
                    update_contacts(username, target_username)
                elif target_username == username and received_username:
                    print(f"Found user {received_username} broadcasting from {sender_ip}")
                    contacts.add(received_username)
                    update_contacts(username, received_username)

                print("Current contacts:", contacts)
    except KeyboardInterrupt:
        print("Stopping broadcast listener...")
    except OSError as e:
        print(f"Error listening for broadcasts: {e}")
    finally:
        sock.close()




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
