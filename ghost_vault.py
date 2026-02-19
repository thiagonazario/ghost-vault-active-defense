import boto3
import base64
import logging
import os
from botocore.exceptions import ClientError

# Ghost Vault - Hardened by Design
# Active Defense Layer for Sovereign Cloud Security
# ---------------------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [GHOST_VAULT] - %(levelname)s: %(message)s')

class GhostVault:
    def __init__(self, key_alias=None, region='us-east-1'):
        """
        Initializes the Sovereign Vault.
        Uses Environment Variables for sensitive ARNs and endpoints.
        """
        self.region = region
        self.kms = boto3.client('kms', region_name=self.region)
        self.sns = boto3.client('sns', region_name=self.region)
        
        # Security Best Practice: Load ARNs from environment to keep repo clean
        self.key_alias = key_alias or os.getenv('GHOST_KMS_ALIAS', 'alias/ghost-protocol-key')
        self.sns_topic_arn = os.getenv('GHOST_SNS_TOPIC_ARN')
        self.admin_email = os.getenv('GHOST_ADMIN_EMAIL')

    def apply_resilience_shield(self):
        """
        [LAZARUS SCRIPT]
        Ensures the alert channel is shielded and indestructible.
        """
        if not self.sns_topic_arn or not self.admin_email:
            logging.error("Resilience Shield: Missing SNS_ARN or ADMIN_EMAIL environment variables.")
            return

        try:
            # 1. Integrity Check: Ensure Admin is actively subscribed
            subscriptions = self.sns.list_subscriptions_by_topic(TopicArn=self.sns_topic_arn)
            
            # Find the specific Subscription ARN for the Admin Email
            admin_sub_arn = next(
                (sub['SubscriptionArn'] for sub in subscriptions.get('Subscriptions', [])
                 if sub['Endpoint'] == self.admin_email and sub['SubscriptionArn'].startswith('arn:aws:sns')),
                None
            )

            if not admin_sub_arn:
                logging.warning(f"Resilience Alert: Admin {self.admin_email} missing or pending. Re-subscribing...")
                self.sns.subscribe(
                    TopicArn=self.sns_topic_arn,
                    Protocol='email',
                    Endpoint=self.admin_email
                )
            else:
                # 2. Hardening the SPECIFIC Subscription: Disable Unsubscribe without Signature
                self.sns.set_subscription_attributes(
                    SubscriptionArn=admin_sub_arn,
                    AttributeName='AllowUnsubscribeWithoutSignature',
                    AttributeValue='false'
                )
                logging.info(f"Sovereign Shield: Signature protection ENABLED for subscription {admin_sub_arn[:20]}...")
                logging.info(f"Integrity Check: Admin {self.admin_email} is actively monitoring the Vault.")

        except ClientError as e:
            logging.error(f"Resilience Shield Failure: {e.response['Error']['Message']}")

    def harden_secret(self, plaintext_secret):
        """ENCRYPT: Transforms the secret into a shielded artifact."""
        try:
            logging.info("Initiating artifact hardening...")
            response = self.kms.encrypt(
                KeyId=self.key_alias,
                Plaintext=plaintext_secret.encode('utf-8')
            )
            return base64.b64encode(response['CiphertextBlob']).decode('utf-8')
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
            msg = f"Decryption Denied! Type: {e.response['Error']['Code']}"
            logging.critical(f"SECURITY ALERT: {msg}")
            self._trigger_active_defense(msg)
            raise e

    def _trigger_active_defense(self, alert_msg):
        """Active Defense Trigger: Reports critical failures directly to SNS."""
        try:
            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Message=f"🚨 [GHOST_VAULT_CRITICAL]: {alert_msg}",
                Subject="Sovereign Infrastructure Breach Attempt"
            )
            logging.warning("Active Defense Alert dispatched.")
        except Exception as e:
            logging.error(f"Failed to dispatch SNS alert: {e}")

if __name__ == "__main__":
    # Tactical Execution
    vault = GhostVault()
    vault.apply_resilience_shield()
    print("Ghost Vault Active Defense & Resilience System Operational.")