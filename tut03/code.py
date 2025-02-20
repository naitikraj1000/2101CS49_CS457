def get_user_criteria():
    print("\nAvailable criteria:")
    print("1. Uppercase letters (A-Z)")
    print("2. Lowercase letters (a-z)")
    print("3. Numbers (0-9)")
    print("4. Special characters (!, @, #)")
    
    while True:
        try:
            criteria = input("\nEnter the criteria numbers you want to check (e.g., 1,2,3): ")
            selected = [int(x.strip()) for x in criteria.split(',')]
            if all(1 <= x <= 4 for x in selected):
                return selected
            print("Please enter valid criteria numbers (1-4)")
        except ValueError:
            print("Please enter numbers separated by commas")

def validate_password(password, selected_criteria):
    # Check minimum length first
    if len(password) < 8:
        print(f"Password '{password}' is invalid: Less than 8 characters")
        return False
    
    # Define criteria checking functions
    has_uppercase = lambda p: any(c.isupper() for c in p)
    has_lowercase = lambda p: any(c.islower() for c in p)
    has_numbers = lambda p: any(c.isdigit() for c in p)
    has_special = lambda p: any(c in "!@#" for c in p)
    
    # Check for invalid special characters
    special_chars = set(c for c in password if not c.isalnum())
    invalid_special = special_chars - set("!@#")
    if invalid_special:
        print(f"Password '{password}' is invalid: Contains invalid special characters: {invalid_special}")
        return False
    
    # Map criteria numbers to validation functions
    criteria_map = {
        1: ("uppercase letters", has_uppercase),
        2: ("lowercase letters", has_lowercase),
        3: ("numbers", has_numbers),
        4: ("special characters", has_special)
    }
    
    # Check selected criteria
    failed_criteria = []
    for num in selected_criteria:
        name, check_func = criteria_map[num]
        if not check_func(password):
            failed_criteria.append(name)
    
    if failed_criteria:
        print(f"Password '{password}' is invalid: Missing {', '.join(failed_criteria)}")
        return False
    
    print(f"Password '{password}' is valid")
    return True

def main():
    password_list = [
        "abc12345",                # Invalid password. Special characters missing
        "abc",                     # Invalid password. Less than 8 Characters
        "123456789",              # Invalid password. Missing special chars, uppercase, lowercase
        "abcdefg$",               # Invalid password. Missing uppercase, numbers
        "abcdefgABHD!@313",       # Valid password
        "abcdefgABHD$$!@313"      # Invalid password. Contains invalid special char
    ]
    # input_password = input("Enter Password to check")
    # password_list = input_password.split()
    
    print("Password Validator")
    selected_criteria = get_user_criteria()
    print(f"\nChecking passwords with selected criteria: {selected_criteria}")
    print("=" * 50)
    
    for password in password_list:
        validate_password(password, selected_criteria)
        print("-" * 50)

if __name__ == "__main__":
    main()
