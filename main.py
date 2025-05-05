import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)

def caesar_encrypt(text, shift):
    """
    Encrypts the given text using Caesar cipher with the specified shift.
    """
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower() and shifted > ord('z'):
                shifted -= 26
            elif char.isupper() and shifted > ord('Z'):
                shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    """
    Decrypts the given text using Caesar cipher with the specified shift.
    """
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)

def is_strong_password(password):
    """
    Check if the password is strong.
    """
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    )

# Password generator function (optional)

def generate_password():
    """
    Generate a strong random password of user-specified length (>=8).
    """
    while True:
        try:
            length = int(input("Enter desired password length: "))
            while length < 8:
                print("Your password should be at least 8 characters long. Please enter a new length.")
                length = int(input("Enter desired password length: "))
            break  # length is valid, exit the outer loop
        except ValueError:
            print("Please enter a valid integer.")
            continue

    characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    while True:
        password = ''.join(random.choices(characters, k=length))
        if is_strong_password(password):
            return password

# Initialize empty lists to store encrypted passwords, websites, and usernames

encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password 

def add_password():
    """
    Prompt the user for website, username, and password.
    Optionally generate a strong password.
    Encrypts and stores the password.
    """
    website = input("Enter website: ")
    username = input("Enter username: ")
    choice = input("Do you want to generate a random strong password? (yes/no): ").strip().lower()
    if choice == 'yes':
        password = generate_password()
        print(f"Generated password: {password}")
    else:
        password = input("Enter password: ")
        if not is_strong_password(password):
            print("Warning: The password is not strong enough.")

    encrypted_password = caesar_encrypt(password, 3)
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted_password)
    print("Password added successfully.")

# Function to retrieve a password 

def get_password():
    """
    Retrieve and display the username and decrypted password for a given website.
    """
    website = input("Enter website to retrieve password: ")
    try:
        index = websites.index(website)
        username = usernames[index]
        encrypted_password = encrypted_passwords[index]
        password = caesar_decrypt(encrypted_password, 3)
        print(f"Username: {username}")
        print(f"Password: {password}")
    except ValueError:
        print("Website not found.")

# Function to save passwords to a JSON file 

def save_passwords():
    """
    Save all passwords, usernames, and websites to 'vault.txt' in JSON format.
    Passwords remain encrypted.
    """
    data = [
        {"website": websites[i], "username": usernames[i], "password": encrypted_passwords[i]}
        for i in range(len(websites))
    ]
    with open("vault.txt", "w") as f:
        json.dump(data, f)
    print("Passwords saved successfully.")

# Function to load passwords from a JSON file 

def load_passwords():
    """
    Load all passwords, usernames, and websites from 'vault.txt'.
    Populates the lists with loaded data.
    """
    try:
        with open("vault.txt", "r") as f:
            data = json.load(f)
        websites.clear()
        usernames.clear()
        encrypted_passwords.clear()
        for entry in data:
            websites.append(entry["website"])
            usernames.append(entry["username"])
            encrypted_passwords.append(entry["password"])
        print("Passwords loaded successfully.")
    except FileNotFoundError:
        print("No saved password file found.")

  # Main method

def main():
    menu = """
Password Manager Menu:
1. Add Password
2. Get Password
3. Save Passwords
4. Load Passwords
5. Quit
"""
    while True:
        print(menu)
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
        elif choice == "5":
            print("Safe browsing!")
            break
        else:
            print("Invalid choice. Please try again.")

# Execute the main function when the program is run

if __name__ == "__main__":
    main()
