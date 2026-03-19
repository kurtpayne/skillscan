# Secrets Manager Integration
Integrate HashiCorp Vault or AWS Secrets Manager into your application.

## Why use a secrets manager
Environment variables are convenient but have limitations: they're visible to all processes, logged in crash dumps, and hard to rotate without redeployment. A secrets manager provides:
- Centralized secret storage with audit logging
- Automatic rotation for supported secret types
- Fine-grained access control (which service can read which secret)
- Secret versioning and rollback

## AWS Secrets Manager setup
```python
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='prod/myapp/db-password')
```

## Vault setup
```python
import hvac
client = hvac.Client(url='https://vault.example.com', token=os.environ['VAULT_TOKEN'])
secret = client.secrets.kv.read_secret_version(path='myapp/db-password')
```

## Migration path
1. Move secrets from environment variables to the secrets manager
2. Update application code to fetch secrets at startup
3. Remove secrets from environment variable configuration
4. Audit who has access to each secret
