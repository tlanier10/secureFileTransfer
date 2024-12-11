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
        find_user(account_info)
      else:
        print(f"Unknown command: {command}")
  except KeyboardInterrupt:
    exit()
  finally:
      del account_info
      gc.collect()

def load_username(filename="accounts.json"):
    """Loads the current user's username (email) from the accounts file."""
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as file:
                account_info = json.load(file)
                return account_info.get("email", None)  # Return the email if it exists
        else:
            print("No accounts file found.")
            return None
    except Exception as e:
        print(f"Error while loading username: {e}")
        return None
      

def find_user(account_info):
    """Automatically finds users broadcasting their presence and adds them as contacts."""
    username = load_username()
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
        message = f"SecureDrop_Email:{send_email};Sender_Email:{username};IP:{local_ip}"



        # Create UDP socket for sending and listening
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', port))  # Bind to listen on the same port

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
                    
                    
                    print(received_username) # 
                    print(sender_ip) # comp 2 ip[]
                    print(send_email) 
                    if received_username == send_email and received_username != username:
                        print(f"Found user {received_username} broadcasting from {sender_ip}")
                        contacts.add(received_username)
                        update_contacts(username, received_username)
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

def update_contacts(username, new_contact, filename="accounts.json"):
    """Updates the contacts list in the accounts file."""
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            data = json.load(file)

        # Initialize contacts list if it doesn't exist
        if "contacts" not in data:
            data["contacts"] = []

        # Avoid duplicates
        if new_contact not in data["contacts"]:
            data["contacts"].append(new_contact)
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
