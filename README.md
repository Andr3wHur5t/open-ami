# Open-AMI

Public versions of my hardened AMIs based on Amazon Linux.

> **Warning:**
>
> This project is designed to provide a starting point to reduce reproduction of work and promote public review.
>
> Additional hardening and detection systems are advised when using these images.


### HAWL1:

**Sumery:** Hardened Amazon Linux With Level 1 CIS Benchmark (HA W L1)

**Use Case:** Base image for better hardened applications

**Key Fratures:**

- Programmatic acceptance tests to verify conformance with CIS level 1
- Designed For Defense in Depth
- AIDE: Host file system integrity based incursion detection system

**Important Notes:**
- Disabled Systems:
  - IPv6
  - Disk Swapping
  - X11 Window Server

**Whishlist:**
- Centralized Logging via AntMan
- BSD Jails
- Bro IDE
- OSQuery
- SELinux
- Auto Configuration Scripts
- Read Only File System

> **NOTE:**
>
> HAWL1 is intended as a base image only; It is your responsibility to understand what hardening is required to handle your use case and threats.

### HAWL1 Bastion

**Sumery:** HAWL1 based SSH & TCP bastion jumpbox.

**Use Case:** Enable authenticated access to private networks.

**Key Features:**

- Allows tunneling exclusively
- Baked Backup Keys
- CA Based SSH Access

### HAWL1 Vault

**Summery:** Hashicorp vault running on HAWL1

**Key Features:**
- Unprivileged Vault Server Managed By Damon
- Dynamodb based HA vault storage
- Unseal Status Reported to CloudWatch
- Only exposes Vault HTTPS api
- Cert Sync Over Encrypted S3

