# Open-AMI

Public versions of my hardened AMIs based on Amazon Linux.

High Level threat models included for each OS.

## Images

**HAWL1**: (Hardened Amazon Linux w\ Level 1 Hardening)
- Conforms to CIS Security Amazon Linux Level 1 Security Benchmark
- Programmatic acceptance tests to verify conformance
- Disabled To Reduce attack surface:
  - X11 Window Server
  - IPv6
  - Disk Swapping
- Host Based Incursion Detection:
  - AIDE FilesSystem Modification monitoring and reporting
- TODOS:
  - BSD Jails
  - BRO IDE
  - OSQuery
  - SELinux
  - Centralized Logging via AntMan
  - Auto Configuration Scripts

> WARNING: HAWL1 is intended as a base image only; you will need to run the finalization script for the security systems to activate fully.
>
> This box should be bolstered in high security environments, please consult your threat model to understand what additional hardening, detection, and incdent responce tools should be added to your box

**HAWL1 Bastion:** (HAWL1 based Jump box)
- Only Offers Tunneling Capability
- Baked Backup Keys
- CA Based SSH Access

**HAWL1 Vault:** (HAWL1 based Hashicorp Vault)
- Managed Vault Damon
- Reports Unseal Status to CloudWatch Metrics
- Only Exposes API
- Uses Dynamo DB as a HA backend

