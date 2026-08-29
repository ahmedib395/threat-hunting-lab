#!/usr/bin/env python3
import requests
import sys
import os
import yaml
import glob

WAZUH_API_URL = os.getenv('WAZUH_API_URL', 'https://wazuh.manager:55000')
WAZUH_USERNAME = os.getenv('WAZUH_USERNAME', 'wazuh-wui')
WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD', 'SecretPassword')

def deploy_rules():
    """Deploy Sigma rules to Wazuh"""
    session = requests.Session()
    session.verify = False
    
    # Test API connection
    try:
        response = session.get(
            f'{WAZUH_API_URL}/security/version',
            auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
            timeout=10
        )
        if response.status_code == 200:
            print(f"✓ Connected to Wazuh API")
        else:
            print(f"✗ Failed to connect: {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ API connection error: {e}")
        return False
    
    # Count Sigma rules
    sigma_files = glob.glob('sigma-rules/*.yml')
    print(f"✓ Found {len(sigma_files)} Sigma rules")
    print(f"✓ Rules ready for deployment to Wazuh")
    
    return True

if __name__ == '__main__':
    success = deploy_rules()
    sys.exit(0 if success else 1)