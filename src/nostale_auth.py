# src/nostale_auth.py
import requests
import json
import uuid
import random
from datetime import datetime
import urllib.parse
import time
import hashlib
class NostaleAuth:
    """
    Class for handling authentication with Gameforge for Nostale.
    """
    
    def __init__(self, identity_path, installation_id=None, proxy=False, proxy_ip="", proxy_port="", 
                 proxy_username="", proxy_password=""):
        """
        Initialize NostaleAuth object.
        
        Args:
            identity_path (str): Path to the identity file
            installation_id (str, optional): Installation ID
            proxy (bool, optional): Whether to use a proxy
            proxy_ip (str, optional): Proxy IP address
            proxy_port (str, optional): Proxy port
            proxy_username (str, optional): Proxy username
            proxy_password (str, optional): Proxy password
        """
        from identity import Identity
        from blackbox import BlackBox, EncryptedBlackBox
        
        self.identity = Identity(identity_path, proxy_ip, proxy_port, proxy_username, proxy_password, proxy)
        self.BlackBox = BlackBox
        self.EncryptedBlackBox = EncryptedBlackBox
        
        self.locale = "en-US"  # Default locale
        self.browser_user_agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36"
        self.installation_id = installation_id if installation_id else str(uuid.uuid4())
        self.token = ""
        
        # Initialize proxy settings
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.use_proxy = proxy
        
        # Initialize certificate and version info
        self.init_gf_version()
    
    def get_proxies(self):
        """Get proxy configuration for requests."""
        if not self.use_proxy:
            return None
            
        proxy_auth = ""
        if self.proxy_username and self.proxy_password:
            proxy_auth = f"{self.proxy_username}:{self.proxy_password}@"
            
        proxies = {
            "http": f"socks5://{proxy_auth}{self.proxy_ip}:{self.proxy_port}",
            "https": f"socks5://{proxy_auth}{self.proxy_ip}:{self.proxy_port}"
        }
        return proxies
    
    def authenticate(self, email, password):
        """
        Authenticate with Gameforge.
        
        Args:
            email (str): Email address
            password (str): Password
            
        Returns:
            tuple: (success, challenge_id, wrong_credentials)
        """
        url = "https://spark.gameforge.com/api/v1/auth/sessions"
        headers = {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": self.browser_user_agent,
            "TNT-Installation-Id": self.installation_id,
            "Origin": "spark://www.gameforge.com",
            "Connection": "keep-alive",
            "accept-encoding": "gzip, deflate, br"
        }
        
        # Update identity and create blackbox
        self.identity.update()
        blackbox = self.BlackBox(self.identity)
        
        # Create request body
        content = {
            "blackbox": blackbox.encoded(),
            "email": email,
            "locale": self.locale,
            "password": password
        }
        
        # Send auth request
        try:
            response = requests.post(
                url, 
                headers=headers, 
                json=content,
                proxies=self.get_proxies()
            )
            
            print(f"Authentication response status: {response.status_code}")
            
            # Process response
            if response.status_code != 201:
                if response.status_code == 409:
                    # CAPTCHA required
                    challenge_id = response.headers.get('gf-challenge-id', '').split(';')[0]
                    print(f"CAPTCHA required, challenge ID: {challenge_id}")
                    return False, challenge_id, False
                elif response.status_code == 403:
                    # Wrong credentials
                    print("Incorrect email or password")
                    return False, "", True
                else:
                    # General error
                    print(f"Authentication error: {response.text}")
                    return False, "", False
            
            # Success - store token
            json_response = response.json()
            self.token = json_response.get("token", "")
            print("Authentication successful!")
            return True, "", False
            
        except Exception as e:
            print(f"Error during authentication: {e}")
            return False, "", False
    def get_client_version(self):
        """Get the client version from Gameforge."""
        url = "http://dl.tnt.gameforge.com/tnt/final-ms3/clientversioninfo.json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                return data.get("version")
            return None
        except Exception as e:
            print(f"Error getting client version: {e}")
            return None

    def create_cef_user_agent(self, account_id, client_version):
        """
        Create a CEF user agent with the correct checksum.
        
        Args:
            account_id (str): The account ID
            client_version (str): The client version
            
        Returns:
            str: The CEF user agent
        """
        checksum = self.calc_cef_user_agent_checksum(account_id, client_version)
        return f"Chrome/C{client_version} ({account_id[:2]}{checksum})"

    def calc_cef_user_agent_checksum(self, account_id, client_version):
        """
        Calculate the checksum for the CEF user agent.
        
        Args:
            account_id (str): The account ID
            client_version (str): The client version
            
        Returns:
            str: The checksum
        """
        # Constants from the Go code
        cert_sha256 = "99025da70af1ef39d2acd049018887ef5140daebc6f11d80461bcf8d02f2d36b"
        cert_sha1 = "d68f9401f15791cc396d4d6af3b977bc58ad0002"
        
        # Find first digit in installation ID
        first_digit = None
        for c in self.installation_id:
            if c.isdigit():
                first_digit = int(c)
                break
        
        # If no digit found or even digit
        if first_digit is None or first_digit % 2 == 0:
            # Even hash chain
            cert_hash = cert_sha256
            version_hash = hashlib.sha1(f"C{client_version}".encode()).hexdigest()
            installation_hash = hashlib.sha256(self.installation_id.encode()).hexdigest()
            account_hash = hashlib.sha1(account_id.encode()).hexdigest()
            
            hash_sum = cert_hash + version_hash + installation_hash + account_hash
            final_hash = hashlib.sha256(hash_sum.encode()).hexdigest()
            
            return final_hash[:8]
        else:
            # Odd hash chain
            cert_hash = cert_sha1
            version_hash = hashlib.sha256(f"C{client_version}".encode()).hexdigest()
            installation_hash = hashlib.sha1(self.installation_id.encode()).hexdigest()
            account_hash = hashlib.sha256(account_id.encode()).hexdigest()
            
            hash_sum = cert_hash + version_hash + installation_hash + account_hash
            final_hash = hashlib.sha256(hash_sum.encode()).hexdigest()
            
            return final_hash[-8:]
    def get_accounts(self):
        """
        Get game accounts associated with the authenticated Gameforge account.
        
        Returns:
            dict: Mapping of account IDs to display names
        """
        if not self.token:
            print("Not authenticated. Call authenticate() first.")
            return {}
            
        url = "https://spark.gameforge.com/api/v1/user/accounts"
        headers = {
            "User-Agent": self.browser_user_agent,
            "TNT-Installation-Id": self.installation_id,
            "Origin": "spark://www.gameforge.com",
            "Authorization": f"Bearer {self.token}",
            "Connection": "Keep-Alive"
        }
        
        try:
            response = requests.get(
                url,
                headers=headers,
                proxies=self.get_proxies()
            )
            
            if response.status_code != 200:
                print(f"Error getting accounts: {response.status_code} - {response.text}")
                return {}
                
            json_response = response.json()
            accounts = {}
            
            for key, account_data in json_response.items():
                guls = account_data.get("guls", {})
                if guls.get("game") != "nostale":
                    continue
                    
                accounts[account_data.get("id")] = account_data.get("displayName")
            
            print(f"Found {len(accounts)} Nostale accounts")
            return accounts
            
        except Exception as e:
            print(f"Error getting accounts: {e}")
            return {}
    
    def get_token(self, account_id):
        """
        Get a login token for the specified account using the correct headers and user agent.
        
        Args:
            account_id (str): The account ID
            
        Returns:
            str: The login token
        """
        if not self.token:
            print("Not authenticated. Call authenticate() first.")
            return ""
            
        # Send iovation first
        if not self.send_iovation(account_id):
            print("Iovation request failed - continuing anyway")
        
        # Wait a moment between requests
        time.sleep(1)
        
        # Get client version
        client_version = self.get_client_version()
        if not client_version:
            print("Failed to get client version")
            return ""
        
        # Generate special user agent with correct checksum
        user_agent = self.create_cef_user_agent(account_id, client_version)
        print(f"Generated User-Agent: {user_agent}")
        
        url = "https://spark.gameforge.com/api/v1/auth/thin/codes"
        
        # Use minimal headers based on the Go implementation
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": user_agent,
            "Authorization": f"Bearer {self.token}"
        }
        
        # Add tnt-installation-id only as lowercase
        headers["tnt-installation-id"] = self.installation_id
        
        # Generate GSID
        gsid = f"{uuid.uuid4()}-{random.randint(1000, 9999)}"
        
        # Update identity and create encrypted blackbox
        self.identity.update()
        blackbox = self.EncryptedBlackBox(self.identity, account_id, gsid, self.installation_id)
        
        # Create request body with exactly the same structure
        content = {
            "platformGameAccountId": account_id,
            "gsid": gsid,
            "blackbox": blackbox.encrypted(),
            "gameId": "dd4e22d6-00d1-44b9-8126-d8b40e0cd7c9"  # Nostale game ID
        }
        
        # Send request
        try:
            response = requests.post(
                url,
                headers=headers,
                json=content,
                proxies=self.get_proxies()
            )
            
            print(f"Token response: {response.status_code}")
            
            if response.status_code != 201:
                print(f"Error getting token: {response.status_code} - {response.text}")
                return ""
                
            json_response = response.json()
            token = json_response.get("code", "")
            print(f"Successfully obtained login token")
            return token
            
        except Exception as e:
            print(f"Error getting token: {e}")
            return ""
    
    def send_iovation(self, account_id):
        """
        Send iovation request.
        
        Args:
            account_id (str): The account ID
            
        Returns:
            bool: Whether the request was successful
        """
        # First send OPTIONS request
        if not self.send_iovation_options():
            print("Iovation OPTIONS request failed")
            return False
            
        # Wait a moment to simulate human behavior
        time.sleep(1)
        
        url = "https://spark.gameforge.com/api/v1/auth/iovation"
        headers = {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": self.browser_user_agent,
            "TNT-Installation-Id": self.installation_id,
            "Origin": "spark://www.gameforge.com",
            "Connection": "keep-alive",
            "Authorization": f"Bearer {self.token}"
        }
        
        # Update identity and create blackbox
        self.identity.update()
        blackbox = self.BlackBox(self.identity)
        
        # Create request body
        content = {
            "accountId": account_id,
            "blackbox": blackbox.encoded(),
            "type": "play_now"
        }
        
        print(f"Sending iovation request for account: {account_id}")
        
        # Send request
        try:
            response = requests.post(
                url,
                headers=headers,
                json=content,
                proxies=self.get_proxies()
            )
            
            print(f"Iovation response: {response.status_code} - {response.text}")
            
            if response.status_code != 200:
                print(f"Iovation request failed: {response.status_code} - {response.text}")
                return False
                
            json_response = response.json()
            return json_response.get("status") == "ok"
            
        except Exception as e:
            print(f"Error sending iovation request: {e}")
            return False


    def send_iovation_options(self):
        """
        Send iovation OPTIONS request.
        
        Returns:
            bool: Whether the request was successful
        """
        url = "https://spark.gameforge.com/api/v1/auth/iovation"
        headers = {
            "Accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "access-control-request-headers": "authorization,content-type,tnt-installation-id",
            "access-control-request-method": "POST",
            "Origin": "spark://www.gameforge.com",
            "Connection": "keep-alive",
            "User-Agent": self.browser_user_agent
        }
        
        # Send OPTIONS request
        try:
            response = requests.options(
                url,
                headers=headers,
                proxies=self.get_proxies()
            )
            
            print(f"Iovation OPTIONS response: {response.status_code}")
            return response.status_code == 204
            
        except Exception as e:
            print(f"Error sending iovation options request: {e}")
            return False
    
    def generate_third_type_user_agent_magic(self, account_id):
        """
        Generate a magic string for the user agent.
        
        Args:
            account_id (str): The account ID
            
        Returns:
            str: The magic string
        """
        # Get first digit from installation ID
        first_letter = None
        for c in self.installation_id:
            if c.isdigit():
                first_letter = c
                break
                
        first_two_letters_of_account_id = account_id[:2]
        
        # Different hash techniques based on the first letter
        import hashlib
        if not first_letter or int(first_letter) % 2 == 0:
            cert_hash = hashlib.sha256(self.cert.encode()).hexdigest()
            version_hash = hashlib.sha1(self.chrome_version.encode()).hexdigest()
            installation_id_hash = hashlib.sha256(self.installation_id.encode()).hexdigest()
            account_id_hash = hashlib.sha1(account_id.encode()).hexdigest()
            
            hash_sum = cert_hash + version_hash + installation_id_hash + account_id_hash
            hash_of_sum = hashlib.sha256(hash_sum.encode()).hexdigest()
            
            return first_two_letters_of_account_id + hash_of_sum[:8]
        else:
            cert_hash = hashlib.sha1(self.cert.encode()).hexdigest()
            version_hash = hashlib.sha256(self.chrome_version.encode()).hexdigest()
            installation_id_hash = hashlib.sha1(self.installation_id.encode()).hexdigest()
            account_id_hash = hashlib.sha256(account_id.encode()).hexdigest()
            
            hash_sum = cert_hash + version_hash + installation_id_hash + account_id_hash
            hash_of_sum = hashlib.sha256(hash_sum.encode()).hexdigest()
            
            return first_two_letters_of_account_id + hash_of_sum[-8:]
    
    def init_gf_version(self):
        """Initialize Gameforge version information."""
        # These values would normally be retrieved from Gameforge
        self.chrome_version = "C72.0.3626.121"
        self.gameforge_version = "2.0.0"
        
        # Certificate from the original code
        self.cert = "-----BEGIN CERTIFICATE-----\nMIIC1jCCAb6gAwIBAgIUGrzMmL1EyuyvfowIQTbYaEXcABgwDQYJKoZIhvcNAQEL\nBQAwcTELMAkGA1UEBhMCREUxEjAQBgNVBAgTCUthcmxzcnVoZTEbMBkGA1UEBxMS\nQmFkZW4tV3VlcnR0ZW1iZXJnMRowGAYDVQQKExFHYW1lZm9yZ2UgNEQgR21iSDEV\nMBMGA1UEAxMMRXZlbnQgSW5nZXN0MB4XDTIyMDQwNjA5NDgwMFoXDTI3MDQwNTA5\nNDgwMFowHjEcMBoGA1UEAxMTRXZlbnQgSW5nZXN0IENsaWVudDBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABB8rLOihh0grHRUKuBouT0DgmByjAXxbX1F18fDYTRLI\nbXA3WxjN2HHHrGQEUVuuwQ08TcwpZL6EA+r/OvV9gIqjgYMwgYAwDgYDVR0PAQH/\nBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0O\nBBYEFDmjgYgc0Pj23L9ISbFRXGpoNWRhMB8GA1UdIwQYMBaAFJhLFyWCrwgACm0N\nGZ0tV6wg5drlMAsGA1UdEQQEMAKCADANBgkqhkiG9w0BAQsFAAOCAQEAcAE+lc0Q\nxrqST4G6RBOy1UziTIdpgBcUDI6k5qF4RjmbTyMSqXPDZn4swq6xo292FRMh1W7I\nq27NtIw0trd3w06yNB65Vb+GgwWlktMtgRArzK20DJunvRfA2B8JU2tuXYJE1w0u\nwBnhqFDO+wUrlEakgNQivEWegfLkGtDzyxsePSyasrhf6XQhkm/QiTnFRK4FLmyi\nibx0gFOKhfung+2Xc8P1L0ySE63m0hPXB3mSYwMHDzfEZc8grjb2b4fGOohDNUTB\nhLIq+2Uqm1nt5BovZhOoDY/iqQH+qTWqt8ixkasITdEY3wvMj4eivOOtT/TsqLNe\nGuGmotYzIhnzhA==\n-----END CERTIFICATE-----"