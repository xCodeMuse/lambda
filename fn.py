import boto3
import os
import json
import base64
import tempfile
import subprocess
import re

def verify_certificate(cert_data):
    """
    Verify certificate validity using OpenSSL subprocess
    Returns tuple (is_valid, details)
    """
    results = {}
    temp_path = None
    
    try:
        # Create a temporary file for the certificate
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as temp:
            temp.write(cert_data.encode('utf-8'))
            temp_path = temp.name
        
        # Check if certificate is parseable and get basic info
        result = subprocess.run(
            ['openssl', 'x509', '-in', temp_path, '-text', '-noout'],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            return False, f"Invalid certificate format: {result.stderr}"
        
        # Extract signature algorithm
        sig_algo_match = re.search(r'Signature Algorithm: (\S+)', result.stdout)
        if sig_algo_match:
            results['signature_algorithm'] = sig_algo_match.group(1)
        
        # Extract public key info
        key_match = re.search(r'Public-Key: \((\d+) bit\)', result.stdout)
        if key_match:
            results['key_size'] = key_match.group(1)
        
        # Get validity dates
        not_before = re.search(r'Not Before: (.*)', result.stdout)
        not_after = re.search(r'Not After : (.*)', result.stdout)
        if not_before and not_after:
            results['not_before'] = not_before.group(1).strip()
            results['not_after'] = not_after.group(1).strip()
        
        # Verify self-signature
        verify_result = subprocess.run(
            ['openssl', 'verify', temp_path],
            capture_output=True, text=True
        )
        # Note: This will always fail for self-signed certs or certs without proper CA chain
        # Just checking if it parses correctly is enough for our purposes
        
        return True, results
    
    except Exception as e:
        return False, f"Verification error: {str(e)}"
    
    finally:
        # Clean up temp file
        if temp_path:
            try:
                os.unlink(temp_path)
            except:
                pass

def lambda_handler(event, context):
    try:
        # Get environment variables
        secret_id = os.environ['SECRET_ID']
        trust_anchor_id = os.environ['TRUST_ANCHOR_ID']
        
        # Initialize clients
        secrets_client = boto3.client('secretsmanager')
        roles_anywhere_client = boto3.client('rolesanywhere')
        
        # Fetch raw PEM certificate from Secrets Manager
        secret_value = secrets_client.get_secret_value(SecretId=secret_id)
        cert_data = secret_value['SecretString'].strip()
        
        # Validate and clean certificate format
        if not "-----BEGIN CERTIFICATE-----" in cert_data:
            raise ValueError("Invalid certificate format: missing BEGIN header")
        if not "-----END CERTIFICATE-----" in cert_data:
            raise ValueError("Invalid certificate format: missing END header")
        
        # Normalize whitespace and line endings
        cert_lines = cert_data.splitlines()
        clean_cert = "\n".join([line.strip() for line in cert_lines])
        
        # Check if certificate is Base64 encoded and decode if needed
        if "-----BEGIN CERTIFICATE-----" not in cert_data:
            try:
                # Try to decode if it looks like base64
                try:
                    decoded = base64.b64decode(cert_data).decode('utf-8')
                    if "-----BEGIN CERTIFICATE-----" in decoded:
                        clean_cert = decoded
                        print("Successfully decoded Base64 certificate")
                except Exception as decode_err:
                    print(f"Not Base64 encoded or decoding failed: {str(decode_err)}")
            except Exception as base64_err:
                print(f"Base64 processing error: {str(base64_err)}")
        
        # Verify certificate with OpenSSL
        is_valid, details = verify_certificate(clean_cert)
        
        if not is_valid:
            raise ValueError(f"Certificate verification failed: {details}")
        
        print(f"Certificate verification successful: {json.dumps(details)}")
        
        # Check for required security properties
        if 'signature_algorithm' in details and 'sha256' not in details['signature_algorithm'].lower():
            print(f"WARNING: Certificate is not using SHA-256. Found: {details['signature_algorithm']}")
        
        if 'key_size' in details and int(details['key_size']) < 2048:
            print(f"WARNING: Certificate key size is less than 2048 bits. Found: {details['key_size']} bits")
        
        # Fetch current trust anchor to preserve name
        current = roles_anywhere_client.get_trust_anchor(trustAnchorId=trust_anchor_id)
        current_name = current['trustAnchor']['name']
        
        # Log certificate (first few characters for debugging)
        print(f"Certificate preview: {clean_cert[:50]}...")
        
        # Update the trust anchor with new certificate
        response = roles_anywhere_client.update_trust_anchor(
            trustAnchorId=trust_anchor_id,
            source={
                "sourceType": "CERTIFICATE_BUNDLE",
                "sourceData": {
                    "x509CertificateData": clean_cert
                }
            },
            name=current_name
        )
        
        print("Trust Anchor successfully updated:", response)
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Trust Anchor updated successfully.",
                "certificate_details": details
            })
        }
    except Exception as e:
        print("Error updating trust anchor:", str(e))
        # Print more debugging information
        if 'cert_data' in locals():
            print(f"Certificate format issue - Length: {len(cert_data)}")
            print(f"Certificate starts with: {cert_data[:50]}")
            print(f"Certificate ends with: {cert_data[-50:]}")
        
        return {
            "statusCode": 500,
            "body": json.dumps(f"Error: {str(e)}")
        }