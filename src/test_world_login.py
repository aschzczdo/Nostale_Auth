# src/test_world_login_fixed.py
import os
import json
import getpass
import time
import logging
from nostale_auth import NostaleAuth
from nostale_connection import NostaleConnection
from nostale_world import NostaleWorldConnection

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WorldLoginTest")

def main():
    # Load config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
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
    
    # Step 1: Authenticate with Gameforge
    logger.info("== Step 1: Authenticating with Gameforge ==")
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
            logger.error("CAPTCHA required. Cannot proceed with test.")
            return
        if wrong_credentials:
            logger.error("Incorrect email or password.")
            return
        logger.error("Authentication failed for unknown reason.")
        return
    
    # Step 2: Get Nostale accounts
    logger.info("== Step 2: Getting Nostale accounts ==")
    accounts = auth.get_accounts()
    
    if not accounts:
        logger.error("No Nostale accounts found.")
        return
    
    # List accounts and let user choose
    print(f"Found {len(accounts)} accounts:")
    account_list = []
    for i, (account_id, display_name) in enumerate(accounts.items()):
        print(f"  {i+1}. {display_name} (ID: {account_id})")
        account_list.append((account_id, display_name))
    
    account_choice = int(input("\nSelect account (number): ")) - 1
    if account_choice < 0 or account_choice >= len(account_list):
        logger.error("Invalid account selection.")
        return
    
    selected_account_id, selected_account_name = account_list[account_choice]
    
    # Step 3: Get login token
    logger.info(f"== Step 3: Getting login token for {selected_account_name} ==")
    token = auth.get_token(selected_account_id)
    
    if not token:
        logger.error("Failed to get login token.")
        return
    
    logger.info("Successfully obtained login token!")
    
    # Step 4: Connect to login server and get NsTest packet
    logger.info("== Step 4: Getting NsTest packet manually ==")
    server = input("Enter server name (Dragonveil, Valehir, Alzanor, or Cosmos): ")
    channel = input("Enter channel number: ")
    
    # Get NsTest packet - but don't rely on the built-in parsing which is failing
    connection = NostaleConnection(token, auth.installation_id, resources_path)
    
    # This part is the manual implementation to get the NsTeST packet
    login_server_ip = "79.110.84.75"
    
    # Determine login server port
    if server.lower() == "dragonveil" or server.lower() == "valehir":
        login_server_port = 4000
    elif server.lower() == "alzanor":
        login_server_port = 4001
    elif server.lower() == "cosmos":
        login_server_port = 4002
    else:
        logger.error("Invalid server name")
        return
    
    # Manual NosTest packet handling
    try:
        # Connect to login server
        logger.info(f"Connecting to login server at {login_server_ip}:{login_server_port}")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        client_socket.connect((login_server_ip, login_server_port))
        
        # Generate NoS0577 packet
        NoS0577 = connection.get_NoS0577_packet()
        logger.info(f"Generated NoS0577 packet: {NoS0577}")
        
        # Send NoS0577 packet
        import socket
        from noscrypto import Client
        
        NoS0577_encrypted = Client.LoginEncrypt(NoS0577.encode("ascii"))
        logger.info(f"Sending encrypted NoS0577 packet (length: {len(NoS0577_encrypted)})")
        client_socket.send(NoS0577_encrypted)
        
        # Receive NsTeST packet
        logger.info("Waiting for server response...")
        data = client_socket.recv(65536)
        if not data:
            logger.error("No data received from login server")
            return
        
        logger.info(f"Received data of length: {len(data)}")
        NsTest = Client.LoginDecrypt(data).decode("ascii", errors="replace")
        logger.info(f"Decrypted NsTest packet: {NsTest}")
        
        # Manual parsing of NsTeST packet
        if not NsTest.startswith("NsTeST"):
            logger.error("Invalid NsTeST packet")
            return
        
        parts = NsTest.split()
        if len(parts) < 2:
            logger.error("Invalid NsTeST packet format")
            return
        
        session_id = parts[1]
        logger.info(f"Session ID: {session_id}")
        
        # Find server entries
        found_server_ip = None
        found_server_port = None
        
        for part in parts:
            if ":" in part and "." in part and server.lower() in part.lower():
                try:
                    server_parts = part.split(":")
                    if len(server_parts) >= 4:
                        ip = server_parts[0]
                        port = int(server_parts[1])
                        server_data = server_parts[3].split(".")
                        
                        if len(server_data) >= 3:
                            world_id = server_data[0]
                            channel_id = server_data[1]
                            server_name = ".".join(server_data[2:])
                            
                            if server.lower() in server_name.lower() and channel_id == channel:
                                found_server_ip = ip
                                found_server_port = port
                                logger.info(f"Found server: {server_name} Channel: {channel_id} at {ip}:{port}")
                                break
                except Exception as e:
                    logger.warning(f"Error parsing server entry: {e}")
        
        if not found_server_ip or not found_server_port:
            logger.error(f"Could not find server {server} with channel {channel}")
            return
        
    except Exception as e:
        logger.error(f"Error processing NsTeST packet: {e}")
        return
    finally:
        # Close socket
        client_socket.close()
    
    # Step 5: Connect to world server
    logger.info("== Step 5: Connecting to world server ==")
    
    # Create world connection with the session ID
    session_id = int(session_id)
    world_conn = NostaleWorldConnection(session_id, installation_id)
    
    # Connect to world server
    if not world_conn.connect(found_server_ip, found_server_port):
        logger.error("Failed to connect to world server")
        return
    
    # Authenticate with world server
    logger.info("Authenticating with world server...")
    if not world_conn.authenticate(selected_account_name):
        logger.error("Failed to authenticate with world server")
        return
    
    logger.info("World server authentication successful!")
    
    # Start pulse thread to keep connection alive
    world_conn.start_pulse_thread()
    
    # Wait for and process character list
    logger.info("Waiting for character list...")
    if not world_conn.wait_for_character_list():
        logger.error("Failed to receive character list")
        world_conn.close()
        return
    
    # Display available characters
    print("\nAvailable characters:")
    for i, char in enumerate(world_conn.character_list):
        print(f"  {i+1}. {char['name']} (ID: {char['id']})")
    
    # Let user select a character
    if len(world_conn.character_list) > 0:
        if len(world_conn.character_list) > 1:
            char_choice = int(input("\nSelect character (number): ")) - 1
            if char_choice < 0 or char_choice >= len(world_conn.character_list):
                logger.error("Invalid character selection, using first character")
                char_choice = 0
        else:
            char_choice = 0
            
        selected_char = world_conn.character_list[char_choice]
        
        # Handle NosVoid PIN if configured
        if 'extra' in config and 'nosvoidPin' in config['extra']:
            world_conn.handle_nosvoid_pin(config['extra']['nosvoidPin'])
        
        # Select character and start game
        if world_conn.select_character_by_id(selected_char['id']):
            logger.info(f"Successfully logged in as {selected_char['name']}!")
            
            # Run a simple loop to handle packets
            logger.info("Entering main packet loop. Press Ctrl+C to exit.")
            try:
                while True:
                    packet = world_conn.receive_packet()
                    if packet:
                        logger.info(f"Received packet: {packet}")
                    
                    time.sleep(0.1)  # Small delay to prevent CPU hogging
                    
            except KeyboardInterrupt:
                logger.info("User interrupted. Closing connection.")
            finally:
                world_conn.close()
        else:
            logger.error("Failed to select character")
            world_conn.close()
    else:
        logger.error("No characters available")
        world_conn.close()

if __name__ == "__main__":
    main()