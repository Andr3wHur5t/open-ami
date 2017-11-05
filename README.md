# Open-AMI

Public versions of my hardened AMIs based on Amazon Linux.

High Level threat models included for each OS.

## Images

**HAWL1**: (Hardened Amazon Linux w\ Level 1 CIS Benchmark)
- Conforms to CIS Security Amazon Linux Level 1 Security Benchmark
- Programmatic acceptance tests to verify conformance
- Disabled Systems (reducing attack surface):
  - IPv6
  - Disk Swapping
  - X11 Window Server
- Host Based Incursion Detection:
  - AIDE FilesSystem Modification monitoring and reporting
- TODO:
  - BSD Jails
  - BRO IDE
  - OSQuery
  - SELinux
  - Centralized Logging via AntMan
  - Auto Configuration Scripts

> **WARNING:**
> It is your responsibility to understand what hardening is required to handle your use case and threats.
>
> This image is designed to provide a starting point to reduce reproduction of work and promote public review.
>
> HAWL1 is intended as a base image only; additional work should be done to fit your use case and threat models.

**HAWL1 Bastion:** (HAWL1 based Jump box)
- Only Offers Tunneling Capability
- Baked Backup Keys
- CA Based SSH Access

**HAWL1 Vault:** (HAWL1 based Hashicorp Vault)
- Managed Vault Damon
- Reports Unseal Status to CloudWatch Metrics
- Only Exposes API
- Uses Dynamo DB as a HA backend

