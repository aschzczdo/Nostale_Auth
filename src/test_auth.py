# src/test_auth.py
import json
import getpass
from nostale_auth import NostaleAuth

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
    installation_id = config.get('installation_id', '')
    
    # Get email and password
    email = input("Gameforge Email: ")
    password = getpass.getpass("Password: ")
    
    # Create NostaleAuth object
    auth = NostaleAuth(
        identity_path,
        installation_id,
        proxy['use_proxy'],
        proxy['host'],
        proxy['port'],
        proxy['username'],
        proxy['password']
    )
    
    # Authenticate
    print("\nAuthenticating...")
    success, challenge_id, wrong_credentials = auth.authenticate(email, password)
    
    if not success:
        if challenge_id:
            print("CAPTCHA required. Cannot proceed with test.")
            return
        if wrong_credentials:
            print("Incorrect email or password.")
            return
        print("Authentication failed for unknown reason.")
        return
    
    # Get accounts
    print("\nGetting accounts...")
    accounts = auth.get_accounts()
    
    if not accounts:
        print("No Nostale accounts found.")
        return
    
    print(f"Found {len(accounts)} accounts:")
    for account_id, display_name in accounts.items():
        print(f"  {display_name} (ID: {account_id})")
    
    # Get token for first account
    if accounts:
        account_id = next(iter(accounts))
        display_name = accounts[account_id]
        
        print(f"\nGetting login token for account: {display_name}")
        token = auth.get_token(account_id)
        
        if token:
            print(f"Login token: {token}")
        else:
            print("Failed to get login token.")
    
    print("\nAuthentication test complete!")

if __name__ == "__main__":
    main()