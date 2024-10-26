import os
import json

file_exists = os.path.exists('registration.json')

if file_exists:
    with open('registration.json', 'r') as file:
        users = json.load(file)

else: 
 
    users = {}

if not users: 
    print("No users are registered with this client.")
    register = input("Do you want to register a new user (y/n)? ").lower()
 
if register == 'y':
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
    
        users[email] = { 
            'name': name,
            'password': password
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
