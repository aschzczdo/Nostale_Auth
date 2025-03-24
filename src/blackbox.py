# src/blackbox.py
import json
import base64
import urllib.parse
import random
import hashlib

class BlackBox:
    """
    Class for handling Gameforge authentication blackbox encoding and decoding.
    """
    
    BLACKBOX_FIELDS = ["v", "tz", "dnt", "product", "osType", "app", "vendor", "mem", "con", 
                       "lang", "plugins", "gpu", "fonts", "audioC", "width", "height", "depth", 
                       "video", "audio", "media", "permissions", "audioFP", "webglFP", "canvasFP", 
                       "creation", "uuid", "d", "osVersion", "vector", "userAgent", "serverTimeInMS", "request"]
    
    def __init__(self, identity, req=None):
        """
        Initialize a BlackBox object.
        
        Args:
            identity: Identity object containing fingerprint data
            req: Optional request data to include in the fingerprint
        """
        self.identity = identity
        if req is not None:
            identity.set_request(req)
    
    def encode(self, fingerprint):
        """
        Encode a fingerprint into a blackbox string.
        
        Args:
            fingerprint (dict): The fingerprint to encode
            
        Returns:
            str: The encoded blackbox string
        """
        # Create fingerprint array in the correct order
        fingerprint_array = []
        for field in self.BLACKBOX_FIELDS:
            fingerprint_array.append(fingerprint.get(field, None))
        
        # Convert to JSON and encode
        fingerprint_array_str = json.dumps(fingerprint_array, separators=(',', ':'))
        return BlackBox.encode_static(fingerprint_array_str.encode())
    
    @staticmethod
    def encode_static(fingerprint_array_str):
        """
        Static method to encode a fingerprint array string.
        
        Args:
            fingerprint_array_str (bytes): Fingerprint array as JSON bytes
            
        Returns:
            str: The encoded blackbox string
        """
        # URL encode
        uri_encoded = urllib.parse.quote(fingerprint_array_str.decode(), safe="-_!~*.'()")
        
        # Custom encoding similar to the C++ version
        blackbox = bytearray()
        blackbox.append(ord(uri_encoded[0]))
        
        for i in range(1, len(uri_encoded)):
            a = blackbox[i-1]
            b = ord(uri_encoded[i])
            c = (a + b) & 0xFF  # Ensure it stays in byte range
            blackbox.append(c)
        
        # Convert to base64 and replace characters as in the original
        blackbox_b64 = base64.b64encode(blackbox).decode()
        blackbox_b64 = blackbox_b64.replace('/', '_').replace('+', '-').replace('=', '')
        
        return "tra:" + blackbox_b64
    
    @staticmethod
    def decode(blackbox):
        """
        Decode a blackbox string into a fingerprint.
        
        Args:
            blackbox (str): The blackbox string to decode
            
        Returns:
            dict: The decoded fingerprint
        """
        # Remove prefix and restore base64 characters
        decoded_blackbox = blackbox.replace("tra:", "").replace('_', '/').replace('-', '+')
        
        # Add padding if needed
        padding = len(decoded_blackbox) % 4
        if padding:
            decoded_blackbox += '=' * (4 - padding)
            
        # Decode base64
        try:
            decoded_bytes = base64.b64decode(decoded_blackbox)
            
            # Reverse the custom encoding
            uri_decoded = bytearray()
            uri_decoded.append(decoded_bytes[0])
            
            for i in range(1, len(decoded_bytes)):
                b = decoded_bytes[i - 1]
                a = decoded_bytes[i]
                c = (a - b) & 0xFF  # Ensure it stays in byte range
                uri_decoded.append(c)
            
            # URL decode
            fingerprint_str = urllib.parse.unquote(uri_decoded.decode('latin1'))
            
            # Parse JSON array into object
            try:
                fingerprint_array = json.loads(fingerprint_str)
                fingerprint = {}
                
                if len(fingerprint_array) != len(BlackBox.BLACKBOX_FIELDS):
                    print(f"Warning: BlackBox.decode size doesn't match: {len(fingerprint_array)} vs {len(BlackBox.BLACKBOX_FIELDS)}")
                    
                for i, field in enumerate(BlackBox.BLACKBOX_FIELDS[:len(fingerprint_array)]):
                    fingerprint[field] = fingerprint_array[i]
                    
                return fingerprint
                
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON from blackbox: {e}")
                return {}
                
        except Exception as e:
            print(f"Error decoding blackbox: {e}")
            return {}
    
    def encoded(self):
        """
        Get the encoded blackbox for the current identity.
        
        Returns:
            str: The encoded blackbox string
        """
        return self.encode(self.identity.get_fingerprint())


class EncryptedBlackBox(BlackBox):
    """
    Class for handling encrypted blackbox for game authentication.
    """
    
    def __init__(self, identity, account_id, gsid, installation_id):
        """
        Initialize an EncryptedBlackBox object.
        
        Args:
            identity: Identity object containing fingerprint data
            account_id (str): The account ID
            gsid (str): The game session ID
            installation_id (str): The installation ID
        """
        super().__init__(identity, self.create_request(gsid, installation_id))
        self.account_id = account_id
        self.gsid = gsid
    
    def encrypted(self):
        """
        Get the encrypted blackbox.
        
        Returns:
            str: The encrypted blackbox as base64
        """
        # Generate encryption key
        key = (self.gsid + "-" + self.account_id).encode()
        key = hashlib.sha512(key).hexdigest().encode()
        
        # Encode and encrypt the blackbox
        blackbox = self.encode(self.identity.get_fingerprint())
        encrypted = self.encrypt(blackbox.encode(), key)
        
        # Convert to base64
        return base64.b64encode(encrypted).decode()
    
    def encrypt(self, data, key):
        """
        Encrypt data using the key.
        
        Args:
            data (bytes): The data to encrypt
            key (bytes): The encryption key
            
        Returns:
            bytes: The encrypted data
        """
        result = bytearray()
        for i in range(len(data)):
            key_index = i % len(key)
            result.append(data[i] ^ key[key_index] ^ key[len(key) - key_index - 1])
        return bytes(result)
    
    @staticmethod
    def create_request(gsid, installation_id):
        """
        Create a request object for the blackbox.
        
        Args:
            gsid (str): The game session ID
            installation_id (str): The installation ID
            
        Returns:
            dict: The request object
        """
        request = {
            "features": [random.randint(1, 2**31-1)],
            "installation": installation_id,
            "session": gsid.rsplit("-", 1)[0]  # Remove the last part after the last hyphen
        }
        return request