from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def main():
    pass

class Enigma:
    def __init__(self, letter=None, change=None):
        self.letter = letter
        self.change = change
        self.cond = False  # Flag to determine if a custom rotor is set
        self.private_key = None
        self.public_key = None
        self.rotor_mapping = None  # Initialize rotor mapping

    def generate_keys(self):
        """Generates RSA keys for encrypting and decrypting messages."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()  # Generate the public key from the private key f(x) = g(x)

    def encrypt_message(self, message: bytes):
        """Encrypts the plaintext with RSA using OAEP for enhanced security."""
        ciphertext = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_message(self, ciphertext: bytes):
        """Decrypts the ciphertext using RSA."""
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def rotor(self, letters):
        """Transforms letters using the rotor mapping."""
        # Fixed mapping for rotor transformation
        self.rotor_mapping = {  # Store rotor mapping as an attribute
            'A': 'D', 'B': 'E', 'C': 'F', 'D': 'G', 'E': 'H', 
            'F': 'I', 'G': 'J', 'H': 'K', 'I': 'L', 'J': 'M',
            'K': 'N', 'L': 'O', 'M': 'P', 'N': 'Q', 'O': 'R',
            'P': 'S', 'Q': 'T', 'R': 'U', 'S': 'V', 'T': 'W',
            'U': 'X', 'V': 'Y', 'W': 'Z', 'X': 'A', 'Y': 'B', 
            'Z': 'C'
        }

        # If a custom rotor mapping is set, use it
        if self.cond:
            self.rotor_mapping = {chr(65 + i): self.change[i] for i in range(26)}

        message = []

        for letter in letters:
            if letter.isalpha():
                upper_letter = letter.upper()  # Convert to uppercase for mapping
                transformed_letter = self.rotor_mapping[upper_letter]  # Transform using rotor mapping
                # Maintain the original case of the letter
                message.append(transformed_letter if letter.isupper() else transformed_letter.lower())
            else:
                message.append(letter)  # Non-alphabet characters remain unchanged

        return ''.join(message)  # Return the transformed message as a string  # Return the transformed message as a string

    def reflector(self, letters):
        """Reflects letters for additional security."""
        # Simple mapping for reflector
        reflector_map = {
            'A': 'Y', 'Y': 'A', 
            'B': 'R', 'R': 'B', 
            'C': 'U', 'U': 'C', 
            'D': 'H', 'H': 'D', 
            'E': 'Q', 'Q': 'E', 
            'F': 'S', 'S': 'F', 
            'G': 'L', 'L': 'G', 
            'I': 'P', 'P': 'I', 
            'J': 'X', 'X': 'J', 
            'K': 'N', 'N': 'K', 
            'M': 'T', 'T': 'M', 
            'O': 'Z', 'Z': 'O', 
            'V': 'W', 'W': 'V'
        }
        
        reflected_message = []

        for letter in letters:
            if letter.isalpha():
                upper_letter = letter.upper()
                reflected_letter = reflector_map[upper_letter]  # Reflect the letter
                # Maintain the original case
                reflected_message.append(reflected_letter if letter.isupper() else reflected_letter.lower())
            else:
                reflected_message.append(letter)  # Non-alphabet characters remain unchanged

        return ''.join(reflected_message) # Return the reflected message as a string

    def reverse_rotor(self, letters):
        """Reverses the rotor transformation."""
        # Create an inverse mapping for the rotor
        inverse_rotor_mapping = {v: k for k, v in self.rotor_mapping.items()}
        reversed_message = []

        for letter in letters:
            if letter.isalpha():
                upper_letter = letter.upper()
                transformed_letter = inverse_rotor_mapping.get(upper_letter, upper_letter)  # Transform using inverse mapping
                # Maintain the original case of the letter
                reversed_message.append(transformed_letter if letter.isupper() else transformed_letter.lower())
            else:
                reversed_message.append(letter)  # Non-alphabet characters remain unchanged
        
        return ''.join(reversed_message)  # Return the reversed message as a string

    def change_rotor(self, change):
        """Changes the rotor mapping based on user input."""
        self.cond = True
        self.change = change  # Set the custom rotor mapping
        if len(change) != 26 or not all(c.isalpha() for c in change):
            raise ValueError("You must introduce a 26 letter long key")  # Validate the custom rotor mapping

    def encrypt_full(self, message: str):
        """Encrypts the message using rotor and reflector, then RSA."""
        # Step 1: Apply the rotor
        rotor_message = self.rotor(message)
        
        # Step 2: Reflect the message
        reflected_message = self.reflector(rotor_message)
        
        # Step 3: Apply the rotor again
        final_message = self.rotor(reflected_message)
        
        # Step 4: Encrypt the final message with RSA
        return self.encrypt_message(final_message.encode('utf-8'))

    def decrypt_full(self, ciphertext: bytes):
        """Decrypts the ciphertext using RSA, then applies rotor and reflector in reverse."""
        # Step 1: Decrypt with RSA
        decrypted_message = self.decrypt_message(ciphertext).decode('utf-8')
        
        # Step 2: Reverse the rotor
        reverse_rotor_message = self.reverse_rotor(decrypted_message)
        
        # Step 3: Reflect the message
        reflected_message = self.reflector(reverse_rotor_message)
        
        # Step 4: Reverse the rotor again to retrieve the original message
        final_message = self.reverse_rotor(reflected_message)
        
        return final_message

if __name__ == "__main__":
    main()