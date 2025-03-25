# src/test_full_auth.py
import os
import getpass
import json
from nostale_auth import NostaleAuth
from nostale_connection import NostaleConnection

def main():
    # Load config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return
    
    # Get credentials
    identity_path = config['identity_path']
    proxy = config['proxy']
    installation_id = config.get('installation_id', '')
    email = input("Gameforge Email: ")
    password = getpass.getpass("Password: ")
    
    # Create resources directory if it doesn't exist
    resources_path = os.path.join(os.getcwd(), "resources")
    os.makedirs(resources_path, exist_ok=True)
    
    # Authenticate with Gameforge
    print("\n== Step 1: Authenticating with Gameforge ==")
    auth = NostaleAuth(
        identity_path,
        installation_id,
        proxy['use_proxy'],
        proxy['host'],
        proxy['port'],
        proxy['username'],
        proxy['password']
    )
    
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
    
    # Get Nostale accounts
    print("\n== Step 2: Getting Nostale accounts ==")
    accounts = auth.get_accounts()
    
    if not accounts:
        print("No Nostale accounts found.")
        return
    
    # List accounts and let user choose
    print(f"Found {len(accounts)} accounts:")
    account_list = []
    for i, (account_id, display_name) in enumerate(accounts.items()):
        print(f"  {i+1}. {display_name} (ID: {account_id})")
        account_list.append((account_id, display_name))
    
    account_choice = int(input("\nSelect account (number): ")) - 1
    if account_choice < 0 or account_choice >= len(account_list):
        print("Invalid account selection.")
        return
    
    selected_account_id, selected_account_name = account_list[account_choice]
    
    # Get login token
    print(f"\n== Step 3: Getting login token for {selected_account_name} ==")
    token = auth.get_token(selected_account_id)
    
    if not token:
        print("Failed to get login token.")
        return
    
    print(f"Successfully obtained login token!")
    
    # Get server connection
    print("\n== Step 4: Connecting to game server ==")
    server = input("Enter server name (Dragonveil, Valehir, Alzanor, or Cosmos): ")
    channel = input("Enter channel number: ")
    
    connection = NostaleConnection(token, auth.installation_id, resources_path)
    result = connection.get_NsTest(server, channel)
    
    if result["success"]:
        print("\n=== Connection successful! ===")
        print(f"Session: {result['session']}")
        print(f"Game server IP: {result['ip']}")
        print(f"Game server port: {result['port']}")
        print("\nYou can now connect to the game server using these details.")
    else:
        print(f"\nConnection failed: {result['message']}")

if __name__ == "__main__":
    main()