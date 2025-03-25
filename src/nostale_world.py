# src/nostale_world.py
import socket
import struct
import time
import logging
from typing import Dict, Tuple, List, Any, Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NostaleWorld")

class WorldEncryptionStream:
    """
    Handles encryption for world server communication.
    Based on the nosbot.js implementation of EncryptWorldStream.
    """
    ENCRYPTION_TABLE = [0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xFF, 0x00]
    
    def __init__(self, session: int):
        self.session = session
        self.is_first_packet = True
        self.packet_id = 1
    
    def encrypt(self, packet: bytes) -> bytes:
        """Encrypt a packet for the world server."""
        if not isinstance(packet, bytes):
            raise TypeError("Packet must be bytes object")
        
        is_session_packet = self.is_first_packet
        self.is_first_packet = False
        
        # Packet counting - add packet ID at the beginning
        self.packet_id += 1
        packet = f"{self.packet_id} {packet.decode('latin1')}".encode('latin1')
        
        # Pack the packet
        packed_packet = self._pack(packet)
        
        # Session number for encryption method selection
        session_number = (self.session >> 6) & 3
        if is_session_packet:
            session_number = -1
        
        session_key = self.session & 0xff
        result = bytearray(len(packed_packet))
        
        # Apply encryption based on session number
        for i in range(len(packed_packet)):
            if session_number == 0:
                result[i] = (packed_packet[i] + session_key + 0x40) & 0xff
            elif session_number == 1:
                result[i] = (packed_packet[i] - session_key - 0x40) & 0xff
            elif session_number == 2:
                result[i] = ((packed_packet[i] ^ 0xc3) + session_key + 0x40) & 0xff
            elif session_number == 3:
                result[i] = ((packed_packet[i] ^ 0xc3) - session_key - 0x40) & 0xff
            else:
                result[i] = (packed_packet[i] + 0x0f) & 0xff
        
        return bytes(result)
    
    def _pack(self, packet: bytes) -> bytes:
        """Pack a packet using the encryption table."""
        output = []
        mask = self._get_mask(packet)
        pos = 0
        
        while len(mask) > pos:
            # Handle non-packed characters
            current_chunk_len = self._calc_len_of_mask(pos, mask, False)
            for i in range(current_chunk_len):
                if pos >= len(mask):
                    break
                
                if i % 0x7e == 0:
                    output.append(min(current_chunk_len - i, 0xfe))
                
                output.append(packet[pos] ^ 0xff)
                pos += 1
            
            # Handle packed characters
            current_chunk_len = self._calc_len_of_mask(pos, mask, True)
            for i in range(current_chunk_len):
                if pos >= len(mask):
                    break
                
                if i % 0x7e == 0:
                    output.append(min(current_chunk_len - i, 0xfe) | 0x80)
                
                current_value = self.ENCRYPTION_TABLE.index(packet[pos])
                
                if i % 2 == 0:
                    output.append(current_value << 4)
                else:
                    output[-1] |= current_value
                
                pos += 1
        
        output.append(0xff)  # End of packet marker
        return bytes(output)
    
    def _get_mask(self, packet: bytes) -> List[bool]:
        """Generate mask indicating which characters to pack."""
        output = []
        for ch in packet:
            if ch == 0:
                break
            output.append(self._get_mask_part(ch))
        return output
    
    def _get_mask_part(self, ch: int) -> bool:
        """Determine if a character should be packed."""
        if ch == 0:
            return False
        return ch in self.ENCRYPTION_TABLE
    
    def _calc_len_of_mask(self, start: int, mask: List[bool], value: bool) -> int:
        """Calculate length of consecutive mask values."""
        current_len = 0
        for i in range(start, len(mask)):
            if mask[i] == value:
                current_len += 1
            else:
                break
        return current_len

class WorldDecryptionStream:
    """
    Handles decryption for world server communication.
    Based on the nosbot.js implementation of DecryptWorldStream.
    """
    DECRYPTION_TABLE = [0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x0A, 0x00]
    
    def __init__(self):
        self.not_parsed_buffer = None
    
    def decrypt(self, packet: bytes) -> List[bytes]:
        """Decrypt a packet from the world server."""
        if not isinstance(packet, bytes):
            raise TypeError("Packet must be bytes object")
        
        if len(packet) == 0:
            logger.warning("Empty packet received")
            return []
        
        # Add part of old packet to the beginning of packet
        if self.not_parsed_buffer is not None:
            packet = self.not_parsed_buffer + packet
            self.not_parsed_buffer = None
        
        len_packet = len(packet)
        current_decrypted_packet = []
        index = 0
        fully_decrypted_packets = []
        
        while index < len_packet:
            current_byte = packet[index]
            index += 1
            current_decrypted_packet.append(current_byte)
            
            if current_byte == 0xff:
                # Packet end, unpack what we have
                fully_decrypted_packets.append(
                    self._unpack(bytes(current_decrypted_packet))
                )
                current_decrypted_packet = []
                continue
        
        # Save not fully received packet for future
        if len(current_decrypted_packet) > 0:
            self.not_parsed_buffer = bytes(current_decrypted_packet)
        
        return fully_decrypted_packets
    
    def _unpack(self, packet: bytes) -> bytes:
        """Unpack a packet using the decryption table."""
        output = []
        pos = 0
        
        while pos < len(packet):
            if packet[pos] == 0xff:
                break
            
            current_chunk_len = packet[pos] & 0x7f
            is_packed = packet[pos] & 0x80
            pos += 1
            
            if is_packed:
                i = 0
                while i < (current_chunk_len + 1) // 2:
                    if pos >= len(packet):
                        break
                    
                    two_chars = packet[pos]
                    pos += 1
                    
                    left_char = two_chars >> 4
                    output.append(self.DECRYPTION_TABLE[left_char])
                    
                    right_char = two_chars & 0xf
                    if right_char == 0:
                        break
                    
                    output.append(self.DECRYPTION_TABLE[right_char])
                    i += 1
            else:
                for i in range(current_chunk_len):
                    if pos >= len(packet):
                        break
                    
                    output.append(packet[pos] ^ 0xff)
                    pos += 1
        
        return bytes(output)

class NostaleWorldConnection:
    """
    Handles connection to the Nostale world server.
    Based on the nosbot.js implementation of TcpClientManager and NostaleBot.
    """
    
    def __init__(self, session_id: int, installation_id: str):
        """
        Initialize the world connection.
        
        Args:
            session_id: Session ID received from login server
            installation_id: Installation ID used for authentication
        """
        self.session_id = session_id
        self.installation_id = installation_id
        self.socket = None
        self.encryptor = WorldEncryptionStream(session_id)
        self.decryptor = WorldDecryptionStream()
        self.character_list = []
        self.current_character = {"id": 0, "name": "", "map_id": -1, "x": -1, "y": -1, "speed": 16}
        self.pulse_interval = None
    
    def connect(self, ip: str, port: int) -> bool:
        """
        Connect to the world server.
        
        Args:
            ip: World server IP address
            port: World server port
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            logger.info(f"Connecting to world server at {ip}:{port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((ip, port))
            logger.info("Connected to world server!")
            return True
        except Exception as e:
            logger.error(f"Error connecting to world server: {e}")
            return False
    
    def send_packet(self, packet: str) -> bool:
        """
        Send a packet to the world server.
        
        Args:
            packet: Packet string to send
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        if not self.socket:
            logger.error("No connection to world server")
            return False
        
        try:
            # Convert to bytes with latin1 encoding and encrypt
            packet_bytes = packet.encode('latin1')
            encrypted = self.encryptor.encrypt(packet_bytes)
            
            logger.debug(f"Sending packet: {packet}")
            self.socket.send(encrypted)
            return True
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            return False
    
    def receive_packet(self, timeout: float = 1.0) -> Optional[str]:
        """
        Receive a packet from the world server.
        
        Args:
            timeout: Receive timeout in seconds
            
        Returns:
            str: Received packet, or None if no packet received
        """
        if not self.socket:
            logger.error("No connection to world server")
            return None
        
        try:
            self.socket.settimeout(timeout)
            data = self.socket.recv(8192)
            
            if data:
                decrypted_packets = self.decryptor.decrypt(data)
                
                if decrypted_packets:
                    # Return the first packet - you might want to handle multiple packets differently
                    packet = decrypted_packets[0].decode('latin1', errors='replace')
                    logger.debug(f"Received packet: {packet}")
                    return packet
            
            return None
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Error receiving packet: {e}")
            return None
    
    def authenticate(self, login: str, language_id: int = 0) -> bool:
        """
        Authenticate with the world server using NoS0577 token method.
        
        Args:
            login: User login/username
            language_id: Language ID (default: 0)
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        # Send session ID as first packet
        if not self.send_packet(f"{self.session_id}"):
            return False
        
        time.sleep(0.5)
        
        # Send login details
        if not self.send_packet(f"{login} GF {language_id}"):
            return False
        
        # Send GF mode confirmation
        if not self.send_packet("thisisgfmode"):
            return False
        
        return True
    
    def start_pulse_thread(self):
        """Start the pulse thread to keep the connection alive."""
        import threading
        
        def pulse_thread():
            pulse_sec = 60
            while self.socket:
                try:
                    self.send_packet(f"pulse {pulse_sec}")
                    pulse_sec += 60
                    time.sleep(60)
                except Exception as e:
                    logger.error(f"Error in pulse thread: {e}")
                    break
        
        self.pulse_interval = threading.Thread(target=pulse_thread)
        self.pulse_interval.daemon = True
        self.pulse_interval.start()
        logger.info("Pulse thread started")
    
    def wait_for_packet(self, start_text: str, timeout: float = 30.0) -> Optional[str]:
        """
        Wait for a specific packet type.
        
        Args:
            start_text: The packet prefix to wait for
            timeout: Maximum time to wait in seconds
            
        Returns:
            str: The received packet, or None if timeout
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            packet = self.receive_packet(1.0)
            
            if packet and packet.startswith(start_text):
                return packet
        
        logger.warning(f"Timeout waiting for packet: {start_text}")
        return None
    
    def wait_for_character_list(self, timeout: float = 30.0) -> bool:
        """
        Wait for and process the character list.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            bool: True if character list received, False otherwise
        """
        self.character_list = []
        start_time = time.time()
        waiting_for_list = False
        
        while time.time() - start_time < timeout:
            packet = self.receive_packet(1.0)
            
            if not packet:
                continue
            
            # Parse character list start
            if packet == "clist_start 0":
                waiting_for_list = True
                logger.info("Character list started")
                continue
            
            # Parse character entries
            if waiting_for_list and packet.startswith("clist "):
                parts = packet.split(" ")
                if len(parts) >= 3:
                    char_id = int(parts[1])
                    char_name = parts[2]
                    self.character_list.append({"id": char_id, "name": char_name})
                    logger.info(f"Character found: {char_name} (ID: {char_id})")
                
            # Check for list end
            if waiting_for_list and packet == "clist_end":
                logger.info(f"Character list completed: {len(self.character_list)} characters")
                return True
        
        logger.warning("Timeout waiting for character list")
        return False
    
    def select_character(self, char_id: Optional[int] = None, char_name: Optional[str] = None) -> bool:
        """
        Select a character to play.
        
        Args:
            char_id: Character ID to select (prioritized)
            char_name: Character name to select (used if char_id is None)
            
        Returns:
            bool: True if character selected, False otherwise
        """
        if not self.character_list:
            logger.error("No characters available")
            return False
        
        # Find character by ID
        if char_id is not None:
            char = next((c for c in self.character_list if c["id"] == char_id), None)
            if char:
                return self.select_character_by_id(char["id"])
        
        # Find character by name
        if char_name is not None:
            char = next((c for c in self.character_list if c["name"].lower() == char_name.lower()), None)
            if char:
                return self.select_character_by_id(char["id"])
        
        # Select first character if no match
        return self.select_character_by_id(self.character_list[0]["id"])
    
    def select_character_by_id(self, char_id: int) -> bool:
        """
        Select a character by ID.
        
        Args:
            char_id: Character ID to select
            
        Returns:
            bool: True if character selected, False otherwise
        """
        logger.info(f"Selecting character with ID: {char_id}")
        
        if not self.send_packet(f"select {char_id}"):
            return False
        
        # Wait for OK packet
        ok_packet = self.wait_for_packet("OK", 10.0)
        if not ok_packet:
            logger.error("Did not receive OK after character selection")
            return False
        
        # Send game start packets
        self.send_packet("game_start")
        self.send_packet("lbs 0")
        self.send_packet("c_close 1")
        self.send_packet("npinfo 0")
        
        logger.info("Character selected and game started")
        return True
    
    def handle_nosvoid_pin(self, pin: str) -> bool:
        """
        Handle NosVoid pin authentication if needed.
        
        Args:
            pin: PIN to send
            
        Returns:
            bool: True if pin handled, False otherwise
        """
        # Wait for pin request
        pin_packet = self.wait_for_packet("guri 10 4 0 1", 5.0)
        if pin_packet:
            logger.info("Received PIN request, sending PIN")
            return self.send_packet(f"guri 4 4 0 0 {pin}")
        
        return True  # No pin requested
    
    def close(self):
        """Close the connection to the world server."""
        if self.socket:
            self.socket.close()
            self.socket = None
            logger.info("Connection to world server closed")