def caesar_cipher(text, shift, encrypt=True):
    result = ''
    for char in text:
        if char.isalpha():
            # Determine the shift direction based on encrypt flag
            direction = 1 if encrypt else -1
            # Shift the character within the range of 'A' to 'Z' or 'a' to 'z'
            result += chr((ord(char) - ord('A' if char.isupper() else 'a') + direction * shift) % 26 + ord('A' if char.isupper() else 'a'))
        else:
            result += char
    return result

def main():
    # Get user input for message and shift value
    message = input("Enter the message: ")
    shift = int(input("Enter the shift value: "))

    # Choose between encryption and decryption
    action = input("Encrypt or decrypt? (E/D): ").upper()

    if action == 'E':
        encrypted_message = caesar_cipher(message, shift, encrypt=True)
        print("Encrypted message:", encrypted_message)
    elif action == 'D':
        decrypted_message = caesar_cipher(message, shift, encrypt=False)
        print("Decrypted message:", decrypted_message)
    else:
        print("Invalid choice. Please enter 'E' for encryption or 'D' for decryption.")

if __name__ == "__main__":
    main()
