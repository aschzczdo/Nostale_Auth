# src/test_identity.py
import os
import json
from identity import Identity

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
    
    # Print original fingerprint
    print("\nOriginal fingerprint (partial):")
    fp = identity.get_fingerprint()
    for key in ['v', 'creation', 'vector']:
        if key in fp:
            print(f"  {key}: {fp[key]}")
    
    # Update identity
    print("\nUpdating identity...")
    identity.update()
    
    # Print updated fingerprint
    print("\nUpdated fingerprint (partial):")
    fp = identity.get_fingerprint()
    for key in ['v', 'creation', 'vector']:
        if key in fp:
            print(f"  {key}: {fp[key]}")
    
    print("\nIdentity test complete!")

if __name__ == "__main__":
    main()