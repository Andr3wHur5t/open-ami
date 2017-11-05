> **Warning:**
>
> This project is designed to provide a starting point to reduce reproduction of work and promote public review.
>
> Additional hardening and detection systems are advised when using these images.

# Open-AMI

Public versions of my hardened AMIs based on Amazon Linux.

### HAWL1 Vault

**Summery:** [Hashicorp vault](https://www.vaultproject.io/) running on HAWL1

**Usage:** Central secret management solution.

**Key Features:**
- Unprivileged Vault Server Managed By Damon
- [Dynamodb based](https://www.vaultproject.io/docs/configuration/storage/dynamodb.html) HA secret storage backend
- Unseal Status Reported to CloudWatch via custom metrics
- Only exposes Vault HTTPS API
- Cert & Key Sync Over Encrypted S3

### HAWL1 Bastion

**Sumery:** HAWL1 based SSH & TCP bastion jumpbox.

**Use Case:**
- Authenticated [access to private networks](https://cloudacademy.com/blog/aws-bastion-host-nat-instances-vpc-peering-security/).
- [Routing traffic](https://github.com/darkk/redsocks) around restricted networks
- Accessing publicly inaccessible services and dashboards

**Key Features:**

- Allows tunneling exclusively
- Baked Backup Keys
  - Good for emergency access (Primary Authentication Server down, but it's in the secured network)
  - Useful for unsealing a vault in a private network (Use TCP proxy to perform unseal operations over TLS)
- CA Based SSH Access
  - Can be [used with hashicorp vault](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html) to provide short lived access
  - Can use [smart cards via OpenSSH PKCS#11](https://github.com/OpenSC/OpenSC/wiki/OpenSSH-and-smart-cards-PKCS%2311) integration

### HAWL1:

**Sumery:** Hardened Amazon Linux With [Level 1 CIS Benchmark](https://www.cisecurity.org/cis-benchmarks/) (HA W L1)

**Use Case:** Base image for better hardened applications

**Key Fratures:**

- Programmatic [acceptance tests](https://github.com/Andr3wHur5t/open-ami/blob/master/hawl1/validate.sh) to verify conformance with CIS level 1
- Works well with [amazon inspector](http://docs.aws.amazon.com/inspector/latest/userguide/inspector_cis.html)
- Designed to work with [Defense in Depth](https://en.wikipedia.org/wiki/Defense_in_depth_(computing))
- [AIDE](http://aide.sourceforge.net/): Host file system integrity based incursion detection system

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

