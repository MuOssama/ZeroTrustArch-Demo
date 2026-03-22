"""
Zero Trust Client for Flask Web Application
This client demonstrates how to interact with the ZTA-enabled Flask server.
"""

import requests
import uuid
import json
import platform
import psutil
import socket
import datetime

# Server URL
BASE_URL = "http://127.0.0.1:5000"

# Generate a unique device ID based on hardware information
def generate_device_id():
    system_info = {
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'platform_version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'mac_address': ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                               for elements in range(0, 48, 8)][::-1])
    }
    
    # Create a deterministic but unique device ID
    device_string = f"{system_info['hostname']}-{system_info['mac_address']}-{system_info['platform']}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, device_string))

# Device authentication information
class ZeroTrustClient:
    def __init__(self):
        self.device_id = generate_device_id()
        self.token = None
        self.username = None
        self.role = None
    
    def login(self, username, password):
        """Authenticate with the server and get a token"""
        # Collect additional context for risk assessment
        context = {
            'device_id': self.device_id,
            'login_time': datetime.datetime.now().isoformat(),
            'client_version': '1.0.0'
        }
        
        # Send login request
        response = requests.post(
            f"{BASE_URL}/login", 
            json={
                'username': username,
                'password': password,
                'device_id': self.device_id,
                'context': context
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data['token']
            self.username = username
            self.role = data['role']
            print(f"Logged in as {username} with role {self.role}")
            return True
        else:
            print(f"Login failed: {response.json().get('message', 'Unknown error')}")
            return False
    
    def get_auth_headers(self):
        """Generate authorization headers for requests"""
        if not self.token:
            raise Exception("Not authenticated. Please login first.")
        
        return {
            'Authorization': f'Bearer {self.token}',
            'X-Device-ID': self.device_id,
            'X-Client-Time': datetime.datetime.now().isoformat()
        }
    
    def get_data(self):
        """Access protected data endpoint"""
        try:
            response = requests.get(
                f"{BASE_URL}/api/data",
                headers=self.get_auth_headers()
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to get data: {response.json().get('message', 'Unknown error')}")
                return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def create_data(self, data):
        """Send data to protected endpoint"""
        try:
            response = requests.post(
                f"{BASE_URL}/api/data",
                headers=self.get_auth_headers(),
                json=data
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to create data: {response.json().get('message', 'Unknown error')}")
                return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def access_admin(self):
        """Access admin panel (requires admin role)"""
        try:
            response = requests.get(
                f"{BASE_URL}/api/admin",
                headers=self.get_auth_headers()
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to access admin: {response.json().get('message', 'Unknown error')}")
                return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def check_server_health(self):
        """Check server health (unprotected endpoint)"""
        try:
            response = requests.get(f"{BASE_URL}/health")
            return response.json()
        except Exception as e:
            print(f"Error: {e}")
            return None

# Example usage
if __name__ == "__main__":
    client = ZeroTrustClient()
    
    print("Device ID:", client.device_id)
    print("\n=== Zero Trust Client Demo ===\n")
    
    # Try with regular user
    print("Logging in as Bob (regular user)...")
    if client.login("bob", "bob_password"):
        print("\nTrying to access protected data...")
        data = client.get_data()
        print("Data received:", data)
        
        print("\nTrying to create data...")
        result = client.create_data({"sample": "test data"})
        print("Result:", result)
        
        print("\nTrying to access admin panel (should fail)...")
        admin_result = client.access_admin()
        print("Admin Result:", admin_result)
    
    print("\n---\n")
    
    # Try with admin user
    print("Logging in as Alice (admin user)...")
    if client.login("alice", "alice_password"):
        print("\nTrying to access protected data...")
        data = client.get_data()
        print("Data received:", data)
        
        print("\nTrying to access admin panel (should succeed)...")
        admin_result = client.access_admin()
        print("Admin Result:", admin_result)
    
    print("\n---\n")
    
    print("Checking server health...")
    health = client.check_server_health()
    print("Health status:", health)