# src/captcha_solver.py
import requests
import time
import os
from PIL import Image
from io import BytesIO
import logging

logger = logging.getLogger("CaptchaSolver")

class CaptchaSolver:
    """
    Class for handling Gameforge captcha challenges.
    Based on the GflessClient implementation.
    """
    
    def __init__(self, challenge_id, language="en-US"):
        """
        Initialize the captcha solver.
        
        Args:
            challenge_id (str): The challenge ID from Gameforge
            language (str): The language for the captcha
        """
        self.challenge_id = challenge_id
        self.language = language
        self.last_updated = 0
        self.base_url = f"https://image-drop-challenge.gameforge.com/challenge/{challenge_id}/{language}"
        self.headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
            "Origin": "spark://www.gameforge.com",
            "Connection": "Keep-Alive"
        }
    
    def get_challenge(self):
        """
        Get the initial challenge data.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = requests.get(self.base_url, headers=self.headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to get challenge: {response.status_code}")
                return False
            
            json_data = response.json()
            self.last_updated = int(json_data.get("lastUpdated", 0))
            logger.info(f"Got challenge data, last updated: {self.last_updated}")
            return True
        except Exception as e:
            logger.error(f"Error getting challenge: {e}")
            return False
    
    def send_answer(self, answer):
        """
        Send an answer to the captcha challenge.
        
        Args:
            answer (int): The answer (0-3)
            
        Returns:
            bool: True if solved successfully, False otherwise
        """
        try:
            content = {"answer": answer}
            response = requests.post(self.base_url, headers=self.headers, json=content)
            
            if response.status_code != 200:
                logger.error(f"Failed to send answer: {response.status_code}")
                return False
            
            json_response = response.json()
            self.last_updated = int(json_response.get("lastUpdated", 0))
            status = json_response.get("status")
            
            logger.info(f"Answer response: {status}")
            return status == "solved"
        except Exception as e:
            logger.error(f"Error sending answer: {e}")
            return False
    
    def get_text_image(self):
        """
        Get the text image for the captcha.
        
        Returns:
            Image: PIL Image object or None if failed
        """
        try:
            url = f"{self.base_url}/text?{self.last_updated}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to get text image: {response.status_code}")
                return None
            
            return Image.open(BytesIO(response.content))
        except Exception as e:
            logger.error(f"Error getting text image: {e}")
            return None
    
    def get_drag_icons(self):
        """
        Get the drag icons image for the captcha.
        
        Returns:
            Image: PIL Image object or None if failed
        """
        try:
            url = f"{self.base_url}/drag-icons?{self.last_updated}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to get drag icons: {response.status_code}")
                return None
            
            return Image.open(BytesIO(response.content))
        except Exception as e:
            logger.error(f"Error getting drag icons: {e}")
            return None
    
    def get_drop_target_image(self):
        """
        Get the drop target image for the captcha.
        
        Returns:
            Image: PIL Image object or None if failed
        """
        try:
            url = f"{self.base_url}/drop-target?{self.last_updated}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to get drop target: {response.status_code}")
                return None
            
            return Image.open(BytesIO(response.content))
        except Exception as e:
            logger.error(f"Error getting drop target: {e}")
            return None
    
    def save_captcha_images(self, directory="captcha_images"):
        """
        Save the captcha images to a directory for manual solving.
        
        Args:
            directory (str): Directory to save images
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            os.makedirs(directory, exist_ok=True)
            
            text_image = self.get_text_image()
            drag_icons = self.get_drag_icons()
            drop_target = self.get_drop_target_image()
            
            if text_image:
                text_image.save(os.path.join(directory, "text.png"))
            
            if drag_icons:
                drag_icons.save(os.path.join(directory, "drag_icons.png"))
            
            if drop_target:
                drop_target.save(os.path.join(directory, "drop_target.png"))
            
            return text_image and drag_icons and drop_target
        except Exception as e:
            logger.error(f"Error saving captcha images: {e}")
            return False

def solve_captcha_manual(challenge_id, language="en-US"):
    """
    Manual process to solve a captcha.
    
    Args:
        challenge_id (str): The challenge ID
        language (str): The language
        
    Returns:
        bool: True if solved, False otherwise
    """
    solver = CaptchaSolver(challenge_id, language)
    
    if not solver.get_challenge():
        logger.error("Failed to get captcha challenge")
        return False
    
    if not solver.save_captcha_images():
        logger.error("Failed to save captcha images")
        return False
    
    print("\nCaptcha images saved to 'captcha_images' directory")
    print("Please check the images and provide the answer (1-4):")
    
    answer = int(input("Enter answer (1-4): ")) - 1  # Convert to 0-based index
    
    if answer < 0 or answer > 3:
        logger.error("Invalid answer")
        return False
    
    result = solver.send_answer(answer)
    
    if result:
        print("Captcha solved successfully!")
    else:
        print("Incorrect answer or error solving captcha")
    
    return result