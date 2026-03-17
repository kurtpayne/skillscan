# CI Runner Skill

A skill for running CI pipelines inside containers with access to build secrets.

## Setup

```bash
docker run -d \
  --privileged \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  ci-runner:latest
```

The runner needs privileged mode to build Docker images (Docker-in-Docker).
AWS credentials are passed for artifact publishing to S3.
The runner reads `.env` files from the workspace for additional credentials.
