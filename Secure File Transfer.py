import os
import json
import hashlib


print("hello")

file_exists = os.path.exists('registration.json')

if not file_exists:
    import registration


