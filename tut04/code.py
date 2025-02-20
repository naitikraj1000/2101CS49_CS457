import hashlib
import os
import json

DATABASE_PATH = "auth_database.json"

def fetch_database():
    if not os.path.exists(DATABASE_PATH):
        return {}
    with open(DATABASE_PATH, "r") as db_file:
        return json.load(db_file)

def persist_database(auth_data):
    with open(DATABASE_PATH, "w") as db_file:
        json.dump(auth_data, db_file, indent=2)

def generate_credentials(plain_text, existing_salt=None):
    generated_salt = existing_salt or os.urandom(32).hex()
    credential = hashlib.sha256((generated_salt + plain_text).encode())
    return generated_salt, credential.hexdigest()

def create_account(account_name, credential):
    auth_data = fetch_database()
    
    if account_name in auth_data:
        print("Account already exists in system!")
        return False
        
    generated_salt, hashed_credential = generate_credentials(credential)
    auth_data[account_name] = {
        "salt_value": generated_salt,
        "hashed_value": hashed_credential
    }
    
    persist_database(auth_data)
    print("Account creation successful!")
    return True

def authenticate(account_name, credential):
    auth_data = fetch_database()
    
    if account_name not in auth_data:
        print("Authentication failed: Invalid credentials!")
        return False
        
    stored_salt = auth_data[account_name]["salt_value"]
    computed_hash = generate_credentials(credential, stored_salt)[1]
    
    if computed_hash == auth_data[account_name]["hashed_value"]:
        print("Authentication successful!")
        return True
    
    print("Authentication failed: Invalid credentials!")
    return False

def main():
    while True:
        action = input("\nSelect action: (C)reate account, (A)uthenticate, or (E)xit: ").strip().lower()
        
        if action == 'c':
            account = input("Enter account name: ").strip()
            secret = input("Enter secret credential: ").strip()
            create_account(account, secret)
            
        elif action == 'a':
            account = input("Enter account name: ").strip()
            secret = input("Enter secret credential: ").strip()
            authenticate(account, secret)
            
        elif action == 'e':
            print("System shutdown. Goodbye!")
            break
            
        else:
            print("Invalid selection! Please choose C, A, or E.")

if __name__ == "__main__":
    main()
