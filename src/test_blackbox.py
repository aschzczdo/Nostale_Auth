# src/test_blackbox.py
import os
import json
from identity import Identity
from blackbox import BlackBox, EncryptedBlackBox
import uuid
import random
def main():
    # Load config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return
    
    identity_path = config['identity_path']
    proxy = config['proxy']
    
    if not os.path.exists(identity_path):
        print(f"Identity file not found at: {identity_path}")
        return
    
    # Create Identity object
    identity = Identity(
        identity_path,
        proxy['host'],
        proxy['port'],
        proxy['username'],
        proxy['password'],
        proxy['use_proxy']
    )
    
    # Test BlackBox
    print("\nTesting BlackBox encoding...")
    identity.update()
    blackbox = BlackBox(identity)
    encoded_blackbox = blackbox.encoded()
    print(f"Encoded blackbox (first 100 chars): {encoded_blackbox[:100]}...")
    
    # Test BlackBox decoding
    print("\nTesting BlackBox decoding...")
    decoded_fingerprint = BlackBox.decode(encoded_blackbox)
    print("Decoded fingerprint (partial):")
    for key in ['v', 'creation', 'vector']:
        if key in decoded_fingerprint:
            print(f"  {key}: {decoded_fingerprint[key]}")
    
    # Verify the encoding and decoding are consistent
    print("\nVerifying encoding/decoding consistency...")
    for key in ['v', 'creation', 'vector']:
        orig = identity.get_fingerprint().get(key)
        decoded = decoded_fingerprint.get(key)
        if orig == decoded:
            print(f"  {key}: MATCH")
        else:
            print(f"  {key}: MISMATCH - Original: {orig}, Decoded: {decoded}")
    
    # Test EncryptedBlackBox
    print("\nTesting EncryptedBlackBox...")
    # Generate random account ID and GSID
    account_id = str(uuid.uuid4())
    gsid = f"{uuid.uuid4()}-{random.randint(1000, 9999)}"
    installation_id = config.get('installation_id') or str(uuid.uuid4())
    
    encrypted_blackbox = EncryptedBlackBox(identity, account_id, gsid, installation_id)
    encrypted_result = encrypted_blackbox.encrypted()
    
    print(f"Account ID: {account_id}")
    print(f"GSID: {gsid}")
    print(f"Installation ID: {installation_id}")
    print(f"Encrypted blackbox (first 100 chars): {encrypted_result[:100]}...")
    
    print("\nBlackBox test complete!")

if __name__ == "__main__":
    main()