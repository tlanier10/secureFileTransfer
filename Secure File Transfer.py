import os
import json
import hashlib
import gc

if os.path.exists('registration.json'):
    with open('registration.json', 'r') as file:
        users = json.load(file)
else:
    print("No registered users found. Please register first.")
    exit()

email = input("Enter Email Address: ")
password = input("Enter Password: ")

email_hash = hashlib.sha256(email.encode()).hexdigest()
password_hash = hashlib.sha256(password.encode()).hexdigest()

if email_hash in users:
    if users[email_hash]['password'] == password_hash:
        print("Username and Password verified. Welcome!")
    else:
        print("Invalid password. Please try again.")
else:
    print("No registered account found with that email address.")

# Data forgetting from memory after exiting 
email = None
password = None
email_hash = None
password_hash = None
gc.collect()
