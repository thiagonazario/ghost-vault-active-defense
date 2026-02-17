import boto3
import base64
import logging
import os
from botocore.exceptions import ClientError

# Ghost Vault - Hardened by Design
# Active Defense Layer for Sovereign Cloud Security
# ---------------------------------------------------------
# Documentation: Solving Complex Problems with Elegance.

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [GHOST_VAULT] - %(levelname)s: %(message)s')

class GhostVault:
    def __init__(self, key_alias=None, region='us-east-1'):
        """
        Initializes the Sovereign Vault. 
        Uses Environment Variables for sensitive ARNs to follow DevSecOps Standards.
        """
        self.region = region
        self.kms = boto3.client('kms', region_name=self.region)
        self.sns = boto3.client('sns', region_name=self.region)
        
        # Security Best Practice: Never hardcode ARNs in public repositories
        self.key_alias = key_alias or os.getenv('GHOST_KMS_ALIAS', 'alias/ghost-protocol-key')
        self.sns_topic_arn = os.getenv('GHOST_SNS_TOPIC_ARN', 'arn:aws:sns:region:account:placeholder')

    def harden_secret(self, plaintext_secret):
        """ENCRYPT: Transforms the secret into a shielded artifact."""
        try:
            logging.info("Initiating artifact hardening...")
            response = self.kms.encrypt(
                KeyId=self.key_alias,
                Plaintext=plaintext_secret.encode('utf-8')
            )
            ciphertext_b64 = base64.b64encode(response['CiphertextBlob']).decode('utf-8')
            logging.info("Artifact successfully shielded.")
            return ciphertext_b64
        except ClientError as e:
            logging.error(f"HARDENING FAILURE: {e.response['Error']['Message']}")
            return None

    def reveal_secret(self, ciphertext_b64):
        """DECRYPT: Authorized identities only. Triggers Active Defense on failure."""
        try:
            raw_ciphertext = base64.b64decode(ciphertext_b64)
            response = self.kms.decrypt(CiphertextBlob=raw_ciphertext)
            logging.info("Authorized access. Secret revealed in memory.")
            return response['Plaintext'].decode('utf-8')
        except ClientError as e:
            error_code = e.response['Error']['Code']
            msg = f"Decryption Denied! Type: {error_code}"
            logging.critical(f"SECURITY ALERT: {msg}")
            
            # The 'Active Defense' Trigger
            self._trigger_active_defense(msg)
            raise e

    def _trigger_active_defense(self, alert_msg):
        """Bypasses noise and reports directly to the Executive Layer."""
        try:
            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Message=f"🚨 [GHOST_VAULT_CRITICAL]: {alert_msg}",
                Subject="Sovereign Infrastructure Breach Attempt"
            )
            logging.warning("Active Defense Alert dispatched to Executive SNS.")
        except Exception as e:
            logging.error(f"Failed to dispatch SNS alert: {e}")

if __name__ == "__main__":
    # Tactical Execution
    vault = GhostVault()
    print("Ghost Vault Active Defense System Operational.")