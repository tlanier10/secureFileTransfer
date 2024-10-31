import os
import json
import hashlib

file_exists = os.path.exists('registration.json')

#I dont think this will ever get opened with a registration file already

#if file_exists:
#    with open('registration.json', 'r+') as file:
#        try:
#            users = json.load(file)
#        except json.JSONDecodeError:
#            users = {}
#else:
users = {}

if not users:
    print("No users are registered with this client.")
    register = input("Do you want to register a new user (y/n)? ").lower()
 
    if register == 'y' or register == 'yes':
        name = input("Enter Full Name: ")
        email = input("Enter Email Address: ")
        
        while True:
            password = input("Enter Password: ")
            repeat_password = input("Re-Enter Password: ")
            
            if password == repeat_password:
                print("Passwords Match.")
                break
            else:
                print("Passwords don't match. Please try again.")
        sha256 = hashlib.sha256()
        name_hash = hashlib.sha256(name.encode()).hexdigest()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        email_hash = hashlib.sha256(email.encode()).hexdigest()
        users[email_hash] = {
            'name': name_hash,
            'password': password_hash
        }
        
        with open('registration.json', 'w') as file:
            json.dump(users, file)
            
        
        print("User Registered.")
else:
    email = input("Enter Email Address: ")
    password = input("Enter Password: ")
    
    if email in users and users[email]['password'] == password:
        print("Username and Password verified. Welcome.")
    else:
        print("Invalid username or password.")
