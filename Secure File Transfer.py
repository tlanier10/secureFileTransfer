import os
import json
import hashlib
import gc

# Loading the user data
USER_DATA_FILE = 'registration.json'
CONTACTS_FILE = 'contacts.json'

# Loading the registered users
if os.path.exists(USER_DATA_FILE):
    with open(USER_DATA_FILE, 'r') as file:
        users = json.load(file)
else:
    import registration
    exit()

# Login the prompt
email = input("Enter Email Address: ")
password = input("Enter Password: ")

email_hash = hashlib.sha256(email.encode()).hexdigest()
password_hash = hashlib.sha256(password.encode()).hexdigest()

if email_hash in users:
    if users[email_hash]['password'] == password_hash:
        print("Username and Password verified. Welcome!")
    else:
        print("Invalid password. Please try again.")
        exit()
else:
    print("No registered account found with that email address.")
    exit()

# Load or initialize contacts data
if os.path.exists(CONTACTS_FILE):
    with open(CONTACTS_FILE, 'r') as file:
        contacts = json.load(file)
else:
    contacts = {}

def add_contact():
    """Adds a new contact for the logged-in user."""
    contact_name = input("Enter Contact's Full Name: ")
    contact_email = input("Enter Contact's Email Address: ")
    contact_email_hash = hashlib.sha256(contact_email.encode()).hexdigest()

    if email_hash not in contacts:
        contacts[email_hash] = {}

    contacts[email_hash][contact_email_hash] = {
        'name': contact_name,
        'email': contact_email
    }

    with open(CONTACTS_FILE, 'w') as file:
        json.dump(contacts, file)
    print("Contact added successfully.")

def list_contacts():
    """Lists all contacts for the logged-in user."""
    if email_hash in contacts:
        print("Your contacts:")
        for contact_hash, contact_info in contacts[email_hash].items():
            print(f"* {contact_info['name']} <{contact_info['email']}>")
    else:
        print("No contacts found.")

# loop command
while True:
    command = input("Type 'add' to add a contact, 'list' to list contacts, or 'exit' to logout: ").strip().lower()
    if command == "add":
        add_contact()
    elif command == "list":
        list_contacts()
    elif command == "exit":
        print("Logging out.")
        break
    else:
        print("Unknown command. Please try again.")

email = None
password = None
email_hash = None
password_hash = None
gc.collect()