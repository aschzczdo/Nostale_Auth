# src/connect_world.py
import os
import json
import getpass
import time
import logging
import socket
import re
from nostale_auth import NostaleAuth
from nostale_world import NostaleWorldConnection

# Import noscrypto if available
try:
    from noscrypto import Client
except ImportError:
    print("WARNING: noscrypto module not found. Login server communication may fail.")
    # Define dummy encryption/decryption functions
    class Client:
        @staticmethod
        def LoginEncrypt(data):
            encrypted = bytearray()
            for byte in data:
                if isinstance(byte, int):
                    encrypted.append((byte + 15) % 256)
                else:
                    encrypted.append((ord(byte) + 15) % 256)
            return encrypted
            
        @staticmethod
        def LoginDecrypt(data):
            decrypted = bytearray()
            for byte in data:
                decrypted.append((byte - 15) % 256)
            return decrypted

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WorldConnect")

def get_client_version(fname):
    """Get client version from executable."""
    import pefile
    props = {'FixedFileInfo': None, 'StringFileInfo': None, 'FileVersion': None}

    try:
        pe = pefile.PE(fname)
        file_info = pe.VS_FIXEDFILEINFO[0]
        props['FixedFileInfo'] = file_info
        props['FileVersion'] = "{}.{}.{}.{}".format(
            (file_info.FileVersionMS >> 16) & 0xffff,
            file_info.FileVersionMS & 0xffff,
            (file_info.FileVersionLS >> 16) & 0xffff,
            file_info.FileVersionLS & 0xffff
        )
    except Exception as e:
        print(f"Error extracting version info: {e}")

    return props["FileVersion"]
    
def convert_to_hexadecimal(input_string):
    """Convert a string to hexadecimal."""
    hex_string = ""
    for char in input_string:
        hex_value = hex(ord(char)).lstrip("0x")
        hex_string += hex_value
    hex_string = hex_string.upper()
    return hex_string

def calculate_combined_md5(file_path_x, file_path_normal):
    """Calculate combined MD5 hash of both client executables."""
    import hashlib
    
    def calculate_md5(file_path):
        with open(file_path, 'rb') as file:
            data = file.read()
            md5_hash = hashlib.md5(data).hexdigest().upper()
            return md5_hash
            
    md5_x = calculate_md5(file_path_x)
    md5_normal = calculate_md5(file_path_normal)
    
    # Use the original combination method
    concatenated_md5 = md5_x + md5_normal
    final_md5 = hashlib.md5(concatenated_md5.encode()).hexdigest().upper()
    
    return final_md5

def generate_NoS0577_packet(token, installation_id, resources_path):
    """Generate NoS0577 packet."""
    import hashlib
    import random
    import os
    
    # Convert token to hexadecimal
    session_token = convert_to_hexadecimal(token)
    
    # Generate random hex value
    random_value = random.randint(0x00000000, 0x00FFFFFF)
    random_hex_value = format(random_value, '08X')
    
    # Get client version
    client_version = get_client_version(os.path.join(resources_path, "NostaleClientX.exe"))
    
    # Calculate MD5
    file_path_x = os.path.join(resources_path, "NostaleClientX.exe")
    file_path_normal = os.path.join(resources_path, "NostaleClient.exe")
    md5 = calculate_combined_md5(file_path_x, file_path_normal)
    
    # Create packet
    packet = f"NoS0577 {session_token}  {installation_id} {random_hex_value} 0{chr(0xB)}{client_version} 0 {md5}"
    
    logger.info(f"\nNoS0577 Packet Details:")
    logger.info(f"Session Token: {session_token}")
    logger.info(f"Installation ID: {installation_id}")
    logger.info(f"Random Hex: {random_hex_value}")
    logger.info(f"Client Version: {client_version}")
    logger.info(f"MD5: {md5}")
    logger.info(f"Complete Packet: {packet}")
    logger.info(f"Packet Length: {len(packet)}")
    
    return packet

def connect_to_login_server(token, installation_id, resources_path, server_name, channel_number):
    """
    Connect to login server and get NsTeST packet.
    
    Args:
        token (str): Authentication token
        installation_id (str): Installation ID
        resources_path (str): Path to resources directory
        server_name (str): Server name (e.g., "Dragonveil")
        channel_number (str): Channel number
        
    Returns:
        dict: Connection information or error
    """
    login_server_ip = "79.110.84.75"
    
    # Determine login server port based on server name
    if server_name.lower() in ["dragonveil", "valehir"]:
        login_server_port = 4000
    elif server_name.lower() == "alzanor":
        login_server_port = 4001
    elif server_name.lower() == "cosmos":
        login_server_port = 4002
    else:
        return {"success": False, "message": f"Invalid server name: {server_name}"}
    
    client_socket = None
    try:
        # Generate NoS0577 packet
        nos0577_packet = generate_NoS0577_packet(token, installation_id, resources_path)
        
        # Connect to login server
        logger.info(f"Connecting to login server at {login_server_ip}:{login_server_port}")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)
        client_socket.connect((login_server_ip, login_server_port))
        
        # Encrypt and send NoS0577 packet
        encrypted_packet = Client.LoginEncrypt(nos0577_packet.encode("ascii"))
        logger.info(f"Sending encrypted NoS0577 packet (length: {len(encrypted_packet)})")
        client_socket.send(encrypted_packet)
        
        # Receive response
        logger.info("Waiting for server response...")
        data = client_socket.recv(65536)
        
        if not data:
            return {"success": False, "message": "No data received from login server"}
        
        # Decrypt NsTeST packet
        logger.info(f"Received data of length: {len(data)}")
        nstest_packet = Client.LoginDecrypt(data).decode("ascii", errors="replace")
        logger.info(f"Decrypted NsTest packet: {nstest_packet}")
        
        # Parse NsTeST packet directly using regex
        # Extract session ID
        if not nstest_packet.startswith("NsTeST"):
            return {"success": False, "message": "Invalid NsTeST packet format"}
        
        parts = nstest_packet.split()
        if len(parts) < 2:
            return {"success": False, "message": "Invalid NsTeST packet (too short)"}
        
        session_id = parts[1]
        logger.info(f"Session ID: {session_id}")
        
        # Find server entries using regex pattern
        server_pattern = fr'(\d+\.\d+\.\d+\.\d+):(\d+):\d+:(\d+)\.(\d+)\..*{server_name.lower()}'
        server_matches = []
        
        for part in parts:
            if ":" in part and "." in part:
                if server_name.lower() in part.lower():
                    # Check if this contains the correct channel
                    match = re.search(fr'(\d+\.\d+\.\d+\.\d+):(\d+):\d+:(\d+)\.(\d+)\.', part, re.IGNORECASE)
                    if match:
                        ip = match.group(1)
                        port = int(match.group(2))
                        channel_id = match.group(4)
                        
                        if channel_id == channel_number:
                            logger.info(f"Found matching server entry: {part}")
                            return {
                                "success": True,
                                "session": session_id,
                                "ip": ip,
                                "port": port
                            }
                        else:
                            server_matches.append({
                                "entry": part,
                                "ip": ip,
                                "port": port,
                                "channel": channel_id
                            })
        
        # If we didn't find an exact match but found servers with the right name
        if server_matches:
            logger.warning(f"Found {len(server_matches)} servers matching '{server_name}' but none with channel {channel_number}")
            logger.warning("Available channels:")
            for match in server_matches:
                logger.warning(f"  Channel {match['channel']}: {match['ip']}:{match['port']}")
                
            # Use the first match as a fallback
            logger.warning(f"Using first available channel: {server_matches[0]['channel']}")
            return {
                "success": True,
                "session": session_id,
                "ip": server_matches[0]['ip'],
                "port": server_matches[0]['port']
            }
        
        return {"success": False, "message": f"Could not find server '{server_name}' with channel {channel_number}"}
    except Exception as e:
        return {"success": False, "message": f"Error connecting to login server: {e}"}
    finally:
        if client_socket:
            client_socket.close()
            logger.info("Login server socket closed")

def connect_to_world(token, installation_id, resources_path):
    """
    Main function to connect to Nostale world server.
    
    Args:
        token (str): Authentication token
        installation_id (str): Installation ID
        resources_path (str): Path to resources directory
    """
    # Get server and channel from user
    server_name = input("Enter server name (Dragonveil, Valehir, Alzanor, or Cosmos): ")
    channel_number = input("Enter channel number: ")
    username = input("Enter character username: ")
    
    # Connect to login server and get server info
    logger.info("Connecting to login server...")
    server_info = connect_to_login_server(token, installation_id, resources_path, server_name, channel_number)
    
    if not server_info["success"]:
        logger.error(f"Failed to connect to login server: {server_info['message']}")
        return
    
    logger.info("Login server connection successful!")
    logger.info(f"Session ID: {server_info['session']}")
    logger.info(f"World Server: {server_info['ip']}:{server_info['port']}")
    
    # Connect to world server
    logger.info("Connecting to world server...")
    world_conn = NostaleWorldConnection(int(server_info['session']), installation_id)
    
    if not world_conn.connect(server_info['ip'], server_info['port']):
        logger.error("Failed to connect to world server")
        return
    
    # Authenticate with world server
    logger.info("Authenticating with world server...")
    if not world_conn.authenticate(username):
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
    if not world_conn.character_list:
        logger.error("No characters available")
        world_conn.close()
        return
    
    print("\nAvailable characters:")
    for i, char in enumerate(world_conn.character_list):
        print(f"  {i+1}. {char['name']} (ID: {char['id']})")
    
    # Select character
    if len(world_conn.character_list) > 1:
        char_choice = int(input("\nSelect character (number): ")) - 1
        if char_choice < 0 or char_choice >= len(world_conn.character_list):
            logger.error("Invalid character selection, using first character")
            char_choice = 0
    else:
        char_choice = 0
        
    selected_char = world_conn.character_list[char_choice]
    
    # Select character
    logger.info(f"Selecting character: {selected_char['name']}")
    if not world_conn.select_character_by_id(selected_char['id']):
        logger.error("Failed to select character")
        world_conn.close()
        return
    
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
        logger.info("Connection closed")

def main():
    # Check if config file exists
    config_path = 'config.json'
    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        return
    
    # Load config
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return
    
    # Check if resources directory exists
    resources_path = os.path.join(os.getcwd(), "resources")
    if not os.path.exists(resources_path):
        os.makedirs(resources_path)
        logger.info(f"Created resources directory: {resources_path}")
    
    # Get client executables
    client_x_path = os.path.join(resources_path, "NostaleClientX.exe")
    client_path = os.path.join(resources_path, "NostaleClient.exe")
    
    if not os.path.exists(client_x_path) or not os.path.exists(client_path):
        logger.error("Nostale client executables not found in resources directory")
        logger.error("Please make sure both NostaleClientX.exe and NostaleClient.exe are in the resources directory")
        return
    
    # Get credentials
    email = input("Gameforge Email: ")
    password = getpass.getpass("Password: ")
    
    # Get identity path and installation ID from config
    identity_path = config['identity_path']
    installation_id = config.get('installation_id', '')
    proxy = config['proxy']
    
    # Authenticate with Gameforge
    logger.info("Authenticating with Gameforge...")
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
            logger.error("CAPTCHA required. Cannot proceed.")
            return
        if wrong_credentials:
            logger.error("Incorrect email or password.")
            return
        logger.error("Authentication failed for unknown reason.")
        return
    
    logger.info("Authentication successful!")
    
    # Get Nostale accounts
    logger.info("Getting Nostale accounts...")
    accounts = auth.get_accounts()
    
    if not accounts:
        logger.error("No Nostale accounts found.")
        return
    
    # List accounts
    print(f"Found {len(accounts)} accounts:")
    account_list = []
    for i, (account_id, display_name) in enumerate(accounts.items()):
        print(f"  {i+1}. {display_name} (ID: {account_id})")
        account_list.append((account_id, display_name))
    
    # Select account
    account_choice = int(input("\nSelect account (number): ")) - 1
    if account_choice < 0 or account_choice >= len(account_list):
        logger.error("Invalid account selection.")
        return
    
    selected_account_id, selected_account_name = account_list[account_choice]
    
    # Get login token
    logger.info(f"Getting login token for {selected_account_name}...")
    token = auth.get_token(selected_account_id)
    
    if not token:
        logger.error("Failed to get login token.")
        return
    
    logger.info("Successfully obtained login token!")
    
    # Connect to world server
    connect_to_world(token, auth.installation_id, resources_path)

if __name__ == "__main__":
    main()