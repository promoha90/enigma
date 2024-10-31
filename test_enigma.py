import pytest
from enigma import Enigma

def enigma():
    """Fixture to create an Enigma instance with generated keys."""
    enigma_instance = Enigma()
    enigma_instance.generate_keys()
    return enigma_instance

def test_encryption_decryption(enigma):
    """Test full encryption and decryption process."""
    test_message = "HELLO"
    encrypted_message = enigma.encrypt_full(test_message)
    decrypted_message = enigma.decrypt_full(encrypted_message)
    assert test_message == decrypted_message

def test_reflector_transformation(enigma):
    """Test if the reflector transformation is correct with the default mapping."""
    reflected_message = enigma.reflector("HELLO")
    assert reflected_message == "DQGGZ"

def test_reverse_rotor(enigma):
    """Test the reverse rotor transformation returns the original message."""
    original_message = "HELLO"
    rotor_message = enigma.rotor(original_message)
    reversed_message = enigma.reverse_rotor(rotor_message)
    assert reversed_message == original_message

def test_custom_rotor(enigma):
    """Test if custom rotor mapping is applied correctly."""
    custom_mapping = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"  # Custom rotor configuration
    enigma.change_rotor(custom_mapping)
    transformed_message = enigma.rotor("HELLO")
    assert transformed_message != "HELLO"  # Message should be different

def test_invalid_custom_rotor(enigma):
    """Test if invalid custom rotor mapping raises an error."""
    with pytest.raises(ValueError):
        enigma.change_rotor("INVALID_MAPPING")  # Incorrect length, should raise error

if __name__ == "__main__":
    pytest.main()
