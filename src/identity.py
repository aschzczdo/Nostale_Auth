# src/identity.py
import json
import time
import random
import base64
import requests
from datetime import datetime

class Identity:
    def __init__(self, identity_path, proxy_ip="", proxy_port="", proxy_username="", proxy_password="", use_proxy=False):
        """
        Initialize an Identity object to manage Gameforge identity/fingerprint.
        
        Args:
            identity_path (str): Path to the identity.json file
            proxy_ip (str, optional): Proxy IP address
            proxy_port (str, optional): Proxy port
            proxy_username (str, optional): Proxy username
            proxy_password (str, optional): Proxy password
            use_proxy (bool, optional): Whether to use a proxy
        """
        self.filename = identity_path
        self.fingerprint = {}
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.use_proxy = use_proxy
        
        self.init_fingerprint()
    
    def init_fingerprint(self):
        """Load the identity fingerprint from the JSON file."""
        try:
            with open(self.filename, 'r') as file:
                content = file.read()
                self.fingerprint = json.loads(content)
                print(f"Successfully loaded identity from {self.filename}")
        except Exception as e:
            print(f"Error loading identity file: {e}")
    
    def update(self):
        """Update the fingerprint with current values."""
        self.update_vector()
        self.update_server_time()
        self.update_creation()
        self.update_timings()
        self.save()
    
    def update_vector(self):
        """Update the vector part of the fingerprint."""
        current_time_ms = int(time.time() * 1000)
        
        if "vector" in self.fingerprint:
            vector_base64 = self.fingerprint["vector"]
            try:
                content = base64.b64decode(vector_base64)
                content_str = content.decode('latin1')  # Use latin1 to handle all byte values
                
                last_blank_index = content_str.rfind(' ')
                if last_blank_index != -1:
                    old_time_str = content_str[last_blank_index+1:]
                    try:
                        old_time = int(old_time_str)
                        content_str = content_str[:last_blank_index]
                        
                        if old_time + 0x3e8 < current_time_ms:
                            # Update vector with random character
                            content_str = content_str[1:] + chr(random.randint(32, 126))
                            
                        new_vector = content_str + " " + str(current_time_ms)
                        self.fingerprint["vector"] = base64.b64encode(new_vector.encode('latin1')).decode()
                    except ValueError:
                        print("Error updating vector - could not parse old time")
            except Exception as e:
                print(f"Error updating vector: {e}")
    
    def update_creation(self):
        """Update the creation timestamp."""
        now = datetime.utcnow()
        self.fingerprint["creation"] = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    def update_server_time(self):
        """Update the server time."""
        try:
            response = self.get_server_date()
            self.fingerprint["serverTimeInMS"] = response
        except Exception as e:
            print(f"Error updating server time: {e}")
    
    def update_timings(self):
        """Update timing values."""
        self.fingerprint["d"] = random.randint(150, 300)
    
    def set_request(self, request):
        """Set the request field in the fingerprint."""
        self.fingerprint["request"] = request
    
    def get_fingerprint(self):
        """Get the current fingerprint."""
        return self.fingerprint
    
    def get_server_date(self):
        """Get the server date from Gameforge."""
        url = "https://gameforge.com/tra/game1.js"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36"
        }
        
        proxies = None
        if self.use_proxy:
            proxy_auth = ""
            if self.proxy_username and self.proxy_password:
                proxy_auth = f"{self.proxy_username}:{self.proxy_password}@"
                
            proxies = {
                "http": f"socks5://{proxy_auth}{self.proxy_ip}:{self.proxy_port}",
                "https": f"socks5://{proxy_auth}{self.proxy_ip}:{self.proxy_port}"
            }
            
        response = requests.get(url, headers=headers, proxies=proxies)
        date_header = response.headers.get('Date')
        
        # Convert the date header to ISO format
        from email.utils import parsedate_to_datetime
        if date_header:
            dt = parsedate_to_datetime(date_header)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        # Fallback to current time
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    def save(self):
        """Save the fingerprint to the file."""
        try:
            with open(self.filename, 'w') as file:
                json.dump(self.fingerprint, file)
        except Exception as e:
            print(f"Error saving identity file: {e}")