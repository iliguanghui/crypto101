"""Demonstrate RSA-2048 encryption and decryption with OAEP/SHA-256.

Run: python rsa_demo.py --text "Hello, RSA!"
Requires: python -m pip install -r requirements.txt
"""

import argparse
import base64

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    raise SystemExit("Install the dependency: python -m pip install -r requirements.txt")


def main():
    parser = argparse.ArgumentParser(description="RSA encryption and decryption demo")
    parser.add_argument("--text", default="Hello, RSA!", help="Short message to encrypt")
    args = parser.parse_args()
    message = args.text.encode("utf-8")

    # OAEP permits at most k - 2*hLen - 2 bytes: 256 - 64 - 2 = 190.
    max_bytes = 2048 // 8 - 2 * hashes.SHA256().digest_size - 2
    if len(message) > max_bytes:
        parser.error("Message must be at most {} UTF-8 bytes (received {}).".format(
            max_bytes, len(message)))

    # Generate a fresh key pair each run. Keep the private key secret.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    # Anyone with the public key can encrypt a message for its owner.
    ciphertext = public_key.encrypt(message, oaep)

    # The matching private key is needed to decrypt it.
    recovered = private_key.decrypt(ciphertext, oaep)

    print("RSA-2048 with OAEP / SHA-256")
    print("Original:", args.text)
    print("Message size: {} bytes; ciphertext size: {} bytes".format(
        len(message), len(ciphertext)))
    print("Ciphertext (Base64):", base64.b64encode(ciphertext).decode("ascii"))
    print("Decrypted:", recovered.decode("utf-8"))
    print("Round trip successful:", recovered == message)
    print("\nOAEP is randomized: encrypting the same message again produces different ciphertext.")
    print("For larger data, use hybrid encryption: RSA encrypts a symmetric key, not the whole file.")


if __name__ == "__main__":
    main()
