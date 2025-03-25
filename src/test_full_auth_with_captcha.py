# src/test_full_auth_updated.py
import os
import getpass
import json
import logging
from nostale_auth import NostaleAuth
from nostale_connection import NostaleConnection
from nostale_world import NostaleWorldConnection
import time
# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("FullAuthTest")

def better_parse_nstest(nstest_packet):
    """
    Improved parser for NsTeST packet to properly extract server information.
    
    Args:
        nstest_packet (str): The NsTeST packet string
        
    Returns:
        dict: Dictionary containing session ID and server information
    """
    if not nstest_packet.startswith("NsTeST"):
        logger.error("Invalid NsTeST packet format")
        return {"success": False, "message": "Invalid packet format"}
    
    logger.info("Parsing NsTeST packet")
    parts = nstest_packet.split(" ")
    
    # Extract session ID
    if len(parts) < 2:
        return {"success": False, "message": "Invalid NsTeST packet format (too short)"}
    
    session_id = parts[1]
    logger.info(f"Session ID: {session_id}")
    
    # Find server entries
    servers = []
    
    for part in parts:
        if ":" in part and "." in part:  # This looks like a server entry
            try:
                server_parts = part.split(":")
                if len(server_parts) >= 4:  # IP:PORT:COLOR:SERVER_DATA
                    ip = server_parts[0]
                    port = int(server_parts[1])
                    color = int(server_parts[2])
                    
                    # Parse server data
                    server_data = server_parts[3].split(".")
                    if len(server_data) >= 3:
                        world_id = int(server_data[0])
                        channel_id = int(server_data[1])
                        server_name = ".".join(server_data[2:])
                        
                        servers.append({
                            "ip": ip,
                            "port": port,
                            "color": color,
                            "world_id": world_id,
                            "channel_id": channel_id,
                            "name": server_name
                        })
            except Exception as e:
                logger.warning(f"Error parsing server entry '{part}': {e}")
    
    logger.info(f"Found {len(servers)} server entries")
    
    return {
        "success": True,
        "session": session_id,
        "servers": servers
    }

def find_server_channel(nstest_data, server_name, channel_number):
    """
    Find server and channel in parsed NsTeST data.
    
    Args:
        nstest_data (Dict): Parsed NsTeST data
        server_name (str): Server name to find
        channel_number (str): Channel number to find
        
    Returns:
        Dict: Server connection information
    """
    if not nstest_data["success"]:
        return nstest_data
    
    channel_number = str(channel_number)
    server_name_lower = server_name.lower()
    
    logger.info(f"Looking for server '{server_name}' channel {channel_number}")
    
    # Display all available servers for debugging
    for i, server in enumerate(nstest_data["servers"]):
        logger.info(f"Server {i+1}: {server['name']} (Channel: {server['channel_id']})")
    
    # Find matching server
    for server in nstest_data["servers"]:
        if (server_name_lower in server["name"].lower() and 
            str(server["channel_id"]) == channel_number):
            
            logger.info(f"Found matching server: {server['name']} Channel: {server['channel_id']}")
            return {
                "success": True,
                "session": nstest_data["session"],
                "ip": server["ip"],
                "port": server["port"]
            }
    
    return {
        "success": False,
        "message": f"Could not find server '{server_name}' with channel {channel_number}"
    }

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
    
    # Authenticate with Gameforge
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
    
    # Use the updated authenticate method which handles captchas
    success, challenge_id, wrong_credentials = auth.authenticate(email, password, handle_captcha=True)
    
    if not success:
        if challenge_id:
            logger.error("CAPTCHA handling failed. Cannot proceed with test.")
            return
        if wrong_credentials:
            logger.error("Incorrect email or password.")
            return
        logger.error("Authentication failed for unknown reason.")
        return
    
    # Get Nostale accounts
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
    
    # Get login token
    logger.info(f"\n== Step 3: Getting login token for {selected_account_name} ==")
    token = auth.get_token(selected_account_id)
    
    if not token:
        logger.error("Failed to get login token.")
        return
    
    logger.info(f"Successfully obtained login token!")
    
    # Get server connection
    logger.info("\n== Step 4: Connecting to game server ==")
    server = input("Enter server name (Dragonveil, Valehir, Alzanor, or Cosmos): ")
    channel = input("Enter channel number: ")
    
    connection = NostaleConnection(token, auth.installation_id, resources_path)
    result = connection.get_NsTest(server, channel)
    
    # Parse NsTeST packet better using our improved parser
    if not result["success"]:
        # Get the raw NsTeST packet if available
        if "raw_nstest" in result:
            logger.info("Using custom NsTeST packet parser")
            better_result = better_parse_nstest(result["raw_nstest"])
            server_info = find_server_channel(better_result, server, channel)
        else:
            logger.error(f"Connection failed: {result['message']}")
            return
    else:
        # Otherwise proceed with the existing result
        server_info = result
    
    if not server_info["success"]:
        logger.error(f"Connection failed: {server_info.get('message', 'Unknown error')}")
        return
    
    logger.info("\n=== Connection successful! ===")
    logger.info(f"Session: {server_info['session']}")
    logger.info(f"Game server IP: {server_info['ip']}")
    logger.info(f"Game server port: {server_info['port']}")
    
    # Step 5: Connect to world server
    logger.info("\n== Step 5: Connecting to world server ==")
    
    # Create world connection
    session_id = int(server_info['session'])
    world_conn = NostaleWorldConnection(session_id, installation_id)
    
    # Connect to world server
    if not world_conn.connect(server_info['ip'], server_info['port']):
        logger.error("Failed to connect to world server")
        return
    
    # Authenticate with world server
    logger.info("Authenticating with world server...")
    if not world_conn.authenticate(selected_account_name):
        logger.error("Failed to authenticate with world server")
        world_conn.close()
        return
    
    logger.info("World server authentication successful!")
    
    # Start pulse thread
    world_conn.start_pulse_thread()
    
    # Wait for character list
    logger.info("Waiting for character list...")
    if not world_conn.wait_for_character_list():
        logger.error("Failed to receive character list")
        world_conn.close()
        return
    
    # Display characters
    print("\nAvailable characters:")
    for i, char in enumerate(world_conn.character_list):
        print(f"  {i+1}. {char['name']} (ID: {char['id']})")
    
    # Let user select character
    if len(world_conn.character_list) > 0:
        if len(world_conn.character_list) > 1:
            char_choice = int(input("\nSelect character (number): ")) - 1
            if char_choice < 0 or char_choice >= len(world_conn.character_list):
                logger.error("Invalid character selection, using first character")
                char_choice = 0
        else:
            char_choice = 0
            
        selected_char = world_conn.character_list[char_choice]
        
        # Select character and start game
        if world_conn.select_character_by_id(selected_char['id']):
            logger.info(f"Successfully logged in as {selected_char['name']}!")
            
            # Main packet loop
            logger.info("Entering main packet loop. Press Ctrl+C to exit.")
            try:
                while True:
                    packet = world_conn.receive_packet()
                    if packet:
                        logger.info(f"Received packet: {packet}")
                    time.sleep(0.1)
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