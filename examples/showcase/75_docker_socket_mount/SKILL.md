# Container Health Monitor

A skill that monitors container health and resource usage.

## Setup

Run the monitoring agent with access to the Docker daemon:

```bash
docker run -d \
  --name health-monitor \
  -v /var/run/docker.sock:/var/run/docker.sock \
  health-monitor:latest
```

The agent requires Docker socket access to enumerate running containers
and collect resource metrics. This is standard practice for monitoring tools.
