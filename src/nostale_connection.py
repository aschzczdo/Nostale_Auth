# src/nostale_connection.py
import socket
import time
import os
import hashlib
import random
import requests
import pefile
from typing import Dict, Tuple, List, Any

class NostaleConnection:
    def __init__(self, token, installation_id, resources_path):
        """
        Initialize NostaleConnection object.
        
        Args:
            token (str): The authentication token
            installation_id (str): The installation ID
            resources_path (str): Path to the resources directory containing Nostale client files
        """
        self.token = token
        self.installation_id = installation_id
        self.resources_path = resources_path
        
    def update_clients(self):
        """Update Nostale client files from Gameforge server."""
        current_directory = os.getcwd()
        paths = []

        url = "https://spark.gameforge.com/api/v1/patching/download/latest/nostale/default?locale=en&architecture=x64&branchToken"
        r = requests.get(url=url)

        for entry in (r.json()["entries"]):
            if entry["file"] == "NostaleClientX.exe":
                download = True
                local_file_path = os.path.join(self.resources_path, "NostaleClientX.exe")
                files = os.listdir(self.resources_path)
                
                for file in files:
                    if self.calculate_sha1(os.path.join(self.resources_path, file)) == entry["sha1"]:
                        download = False
                        
                if download:
                    # Send an HTTP GET request to the URL
                    file_url = f"http://patches.gameforge.com{entry['path']}"
                    response = requests.get(file_url)

                    if response.status_code == 200:
                        with open(local_file_path, 'wb') as file:
                            file.write(response.content)
                        print(f"NostaleClientX.exe updated at: {local_file_path}!")
                    else:
                        print(f"Failed to download file. Status code: {response.status_code}")
                        
                paths.append(local_file_path)

            elif entry["file"] == "NostaleClient.exe":
                download = True
                local_file_path = os.path.join(self.resources_path, "NostaleClient.exe")
                files = os.listdir(self.resources_path)
                
                for file in files:
                    if self.calculate_sha1(os.path.join(self.resources_path, file)) == entry["sha1"]:
                        download = False
                        
                if download:
                    # Send an HTTP GET request to the URL
                    file_url = f"http://patches.gameforge.com{entry['path']}"
                    response = requests.get(file_url)

                    if response.status_code == 200:
                        with open(local_file_path, 'wb') as file:
                            file.write(response.content)
                        print(f"NostaleClient.exe updated at: {local_file_path}!")
                    else:
                        print(f"Failed to download file. Status code: {response.status_code}")
                        
                paths.append(local_file_path)

        return paths
    
    def calculate_sha1(self, file_path):
        sha1_hash = hashlib.sha1()
        if not "Nostale" in str(file_path):
            return 0
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(65536)
                if not data:
                    break
                sha1_hash.update(data)
        return sha1_hash.hexdigest()

    
    def calculate_combined_md5(self):
        """Calculate combined MD5 hash of both Nostale client executables."""
        file_paths = self.update_clients()
        if len(file_paths) < 2:
            raise Exception("Failed to find both Nostale client files")
        
        file_path_x = None
        file_path_normal = None
        
        for path in file_paths:
            if "NostaleClientX.exe" in path:
                file_path_x = path
            elif "NostaleClient.exe" in path:
                file_path_normal = path
        
        if not file_path_x or not file_path_normal:
            raise Exception("Failed to find both Nostale client files")

        def calculate_md5(file_path):
            with open(file_path, 'rb') as file:
                data = file.read()
                md5_hash = hashlib.md5(data).hexdigest().upper()
                return md5_hash

        md5_x = calculate_md5(file_path_x)
        md5_normal = calculate_md5(file_path_normal)

        # OLD method
        concatenated_md5 = md5_x + md5_normal 
        final_md5 = hashlib.md5(concatenated_md5.encode()).hexdigest().upper()

        return final_md5
    
    def convert_to_hexadecimal(self, input_string):
        """Convert a string to hexadecimal."""
        hex_string = ""
        for char in input_string:
            hex_value = hex(ord(char)).lstrip("0x")
            hex_string += hex_value
        hex_string = hex_string.upper()
        return hex_string
    
    def generate_random_hex_value(self):
        """Generate a random hex value."""
        random_value = random.randint(0x00000000, 0x00FFFFFF)
        hex_string = format(random_value, '08X')
        return hex_string
    
    def get_client_version(self, fname):
        """Get client version from executable."""
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
    
    def get_NoS0577_packet(self):
        """Generate NoS0577 packet to match Qt implementation."""
        self.update_clients()

        # Print the original token
        print(f"\nOriginal token before conversion: {self.token}")
        
        session_token = self.convert_to_hexadecimal(self.token)
        
        # Generate random hex value like Qt version (random 100-999 to hex)
        random_decimal = random.randint(100, 999)
        random_hex_value = format(random_decimal, 'x')
        
        client_version = self.get_client_version(os.path.join(self.resources_path, "NostaleClientX.exe"))
        
        # Calculate MD5 as in Qt version
        def calculate_md5(file_path):
            with open(file_path, 'rb') as file:
                data = file.read()
                md5_hash = hashlib.md5(data).hexdigest().upper()
                return md5_hash
                
        md5_clientX = calculate_md5(os.path.join(self.resources_path, "NostaleClientX.exe"))
        md5_client = calculate_md5(os.path.join(self.resources_path, "NostaleClient.exe"))
        concatenated_md5 = md5_clientX + md5_client
        md5 = hashlib.md5(concatenated_md5.encode()).hexdigest().upper()
        
        # Qt format: "region_code + " " + QChar(0xB) + " " + client_version"
        # Using "0" as region_code like in our previous implementation
        region_and_version = "0 " + chr(0xB) + " " + client_version
        
        # Combine into final packet
        packet = f"NoS0577 {session_token}  {self.installation_id} {random_hex_value} 0{chr(0xB)}{client_version} 0 {md5}"
        
        # Print detailed information for debugging
        print("\nNoS0577 Packet Details:")
        print(f"Session Token: {session_token}")
        print(f"Installation ID: {self.installation_id}")
        print(f"Random Hex: {random_hex_value}")
        print(f"Region and Version: {region_and_version}")
        print(f"MD5: {md5}")
        print(f"Complete Packet: {packet}")
        print(f"Packet Length: {len(packet)}")
        
        return packet
    @staticmethod
    def login_encrypt(data):
        """Encrypt login data."""
        encrypted = bytearray()
        for byte in data:
            # Make sure we're adding 15 to the numeric value of each byte
            if isinstance(byte, int):
                encrypted.append((byte + 15) % 256)
            else:
                encrypted.append((ord(byte) + 15) % 256)
        return encrypted

    @staticmethod
    def login_decrypt(data):
        """Decrypt login data."""
        decrypted = bytearray()
        for byte in data:
            decrypted.append((byte - 15) % 256)
        return decrypted
    
    def _parse_NsTest(self, ns_test_str):
        """Parse NsTest packet to extract session and server information."""
        print(f"Parsing NsTest packet: {ns_test_str}")
        if not ns_test_str.startswith("NsTeST"):
            print("Packet does not start with NsTeST")
            return None, None
        
        parts = ns_test_str.split()
        if len(parts) < 2:
            print("Packet has insufficient parts")
            return None, None
        
        session = parts[1]
        servers = {"servers": []}
        
        # Skip NsTeST and session
        parts = parts[2:]
    
        # Process server info in groups of 4
        for i in range(0, len(parts), 4):
            if i + 3 < len(parts):
                server_info = {
                    "server_name": parts[i],
                    "channel": parts[i + 1],
                    "ip": parts[i + 2],
                    "port": parts[i + 3]
                }
                servers["servers"].append(server_info)
        
        return session, servers
    
    def get_NsTest(self, server, channel):
        """
        Connect to the login server and get NsTest packet.
        
        Args:
            server (str): Server name
            channel (str): Channel number
            
        Returns:
            dict: Connection information including session, IP, and port
        """
        login_server_ip = "79.110.84.75"
        
        # Determine login server port
        if server.lower() == "dragonveil" or server.lower() == "valehir":
            login_server_port = 4000
        elif server.lower() == "alzanor":
            login_server_port = 4001
        elif server.lower() == "cosmos":
            login_server_port = 4002
        else:
            return {"success": False, "message": "Invalid server name"}
        
        # Generate NoS0577 packet
        NoS0577 = self.get_NoS0577_packet()
        print(f"Generated NoS0577 packet: {NoS0577}")
        
        client_socket = None
        try:
            # Connect to login server
            print(f"Connecting to login server at {login_server_ip}:{login_server_port}")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)  # Set a 10-second timeout
            client_socket.connect((login_server_ip, login_server_port))
            
            # Send encrypted packet
            NoS0577_encrypted = self.login_encrypt(NoS0577.encode("ascii"))
            print(f"Sending encrypted NoS0577 packet (length: {len(NoS0577_encrypted)})")
            client_socket.send(NoS0577_encrypted)
            
            # Receive response with timeout handling
            print("Waiting for server response...")
            try:
                data = client_socket.recv(65536)
                if data:
                    print(f"Received data of length: {len(data)}")
                    NsTest = self.login_decrypt(data).decode("ascii", errors="replace")
                    print(f"Decrypted NsTest packet: {NsTest}")
                    
                    session, servers = self._parse_NsTest(str(NsTest))
                    if session:
                        print(f"Session: {session}")
                        print(f"Found {len(servers['servers'])} servers")
                        
                        # Find matching server and channel
                        for server_info in servers['servers']:
                            print(f"Checking server: {server_info['server_name']} channel: {server_info['channel']}")
                            if server.lower() in server_info['server_name'].lower() and server_info['channel'] == str(channel):
                                return {
                                    "success": True,
                                    "session": session,
                                    "ip": server_info["ip"],
                                    "port": int(server_info["port"])
                                }
                        return {"success": False, "message": "Unable to find channel/server."}
                    return {"success": False, "message": "Unable to get session."}
                else:
                    return {"success": False, "message": "No data received from login server."}
            except socket.timeout:
                return {"success": False, "message": "Timeout waiting for server response."}
                
        except ConnectionRefusedError:
            return {"success": False, "message": "Connection refused by login server."}
        except socket.gaierror:
            return {"success": False, "message": "Address-related error connecting to login server."}
        except Exception as e:
            return {"success": False, "message": f"Exception during connection: {str(e)}"}
        finally:
            # Close the socket
            if client_socket:
                client_socket.close()
                print("Socket closed")