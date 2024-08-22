import hashlib
import os
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    cat_logo = f"""
{Fore.RED}
 /\_/\  
( o.o ) 
 > ^ <
{Fore.RESET}
"""
    banner = f"{Fore.YELLOW}Welcome to Hashmaker!{Fore.RESET}"
    print(cat_logo)
    print(banner)
    print("-" * 40)

def generate_password_hash(password, hash_type):
    # Encode the password to bytes
    password_bytes = password.encode('utf-8')

    # Create a hash object based on the selected hash type
    if hash_type == 'md5':
        hash_object = hashlib.md5()
    elif hash_type == 'sha1':
        hash_object = hashlib.sha1()
    elif hash_type == 'sha224':
        hash_object = hashlib.sha224()
    elif hash_type == 'sha256':
        hash_object = hashlib.sha256()
    elif hash_type == 'sha384':
        hash_object = hashlib.sha384()
    elif hash_type == 'sha512':
        hash_object = hashlib.sha512()
    else:
        raise ValueError("Unsupported hash type.")

    # Update the hash object with the password bytes
    hash_object.update(password_bytes)

    # Get the hexadecimal representation of the hash
    hashed_password = hash_object.hexdigest()

    return hashed_password

def save_to_file(filename, password, hashed_passwords):
    try:
        with open(filename, 'a') as file:
            file.write(f"Password: {password}\n")
            for hash_type, hashed_password in hashed_passwords.items():
                file.write(f"Hash Type: {hash_type.upper()}\n")
                file.write(f"Hashed Password: {hashed_password}\n")
            file.write("-" * 40 + "\n")
        print(f"{Fore.GREEN}Password and hash(es) saved to {filename}")
    except Exception as e:
        print(f"{Fore.RED}Failed to write to file: {e}")

def main():
    clear_terminal()  # Clear the terminal before displaying anything
    print_banner()  # Print the welcome banner with the cat logo

    # Prompt the user for a password
    password = input(f"{Fore.CYAN}Enter the password to hash: {Fore.RESET}")

    # Display hash type options
    print(f"{Fore.YELLOW}Select a hash type:")
    print(f"{Fore.YELLOW}1. {Fore.RESET}MD5")
    print(f"{Fore.YELLOW}2. {Fore.RESET}SHA-1")
    print(f"{Fore.YELLOW}3. {Fore.RESET}SHA-224")
    print(f"{Fore.YELLOW}4. {Fore.RESET}SHA-256")
    print(f"{Fore.YELLOW}5. {Fore.RESET}SHA-384")
    print(f"{Fore.YELLOW}6. {Fore.RESET}SHA-512")
    print(f"{Fore.YELLOW}7. {Fore.RESET}All (Generate all hash types)")

    # Create a mapping of numbers to hash types
    hash_type_map = {
        '1': 'md5',
        '2': 'sha1',
        '3': 'sha224',
        '4': 'sha256',
        '5': 'sha384',
        '6': 'sha512'
    }

    # Prompt the user for the hash type number
    choice = input(f"{Fore.CYAN}Enter the number corresponding to your choice: {Fore.RESET}")

    if choice in hash_type_map:
        hash_type = hash_type_map[choice]
        # Generate the hashed password
        hashed_password = generate_password_hash(password, hash_type)

        # Display the hashed password
        print(f"{Fore.GREEN}Hashed password ({hash_type.upper()}): {hashed_password}")

        # Ask the user if they want to save the file
        save_choice = input(f"{Fore.CYAN}Do you want to save this to a file? (Y/n): {Fore.RESET}").strip().lower()

        if save_choice in ['y', 'yes', '']:
            # Prompt for the filename to save the hash
            filename = input(f"{Fore.CYAN}Enter the filename to save the password and hash: {Fore.RESET}")

            # Save the password and hash to the file
            save_to_file(filename, password, {hash_type: hashed_password})
        else:
            print(f"{Fore.RED}File not saved.")

    elif choice == '7':
        # Generate hashes for all types
        all_hashes = {}
        for hash_type in hash_type_map.values():
            all_hashes[hash_type] = generate_password_hash(password, hash_type)

        # Display all hashed passwords
        for hash_type, hashed_password in all_hashes.items():
            print(f"{Fore.GREEN}Hashed password ({hash_type.upper()}): {hashed_password}")

        # Ask the user if they want to save the file
        save_choice = input(f"{Fore.CYAN}Do you want to save this to a file? (Y/n): {Fore.RESET}").strip().lower()

        if save_choice in ['y', 'yes', '']:
            # Prompt for the filename to save the hashes
            filename = input(f"{Fore.CYAN}Enter the filename to save the password and hashes: {Fore.RESET}")

            # Save the password and all hashes to the file
            save_to_file(filename, password, all_hashes)
        else:
            print(f"{Fore.RED}File not saved.")
    else:
        print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and 7.")

if __name__ == "__main__":
    main()

