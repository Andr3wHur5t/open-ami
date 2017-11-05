# Bastion

The first line of defense to a private network.

Mount a static `localhost:port` to bastion `targetAddr:port`:

```sh

```

Connect to the bastion using your browser via a dynamic tunnel (SOCKS5):

```sh
```

## Core Mitigations

- Short Lived Access whenever possible (CA sign public key with short ttl)
  - Reasons:
    - Minimize number of keys that have access (less attack surface)
    - Higher resolution audit trail
    - Less reliance on traffic mentoring for detection
- Self destructing hardware tokens for private keys storage
  - Reasons:
    - Many people don't secure ssh keys sufficiently
    - SSH key protection boils down to laptop access and password (passwords are weak)
    - Self destructing key protects against brute force
    - Requires physical access to token to use (No Remote Attacks)
- Monitor traffic and user behavior
  - Reasons:
    - Sophisticated attacks will make it hard for users to know their keys are stolen
    - Enable automated defensive systems
- Only Allow TCP Forwarding:
  - Reasons:
    - In the event the bastion host is compromised privilege escalation through SSH agent forwarding theft is mitigated
    - Reduces risk of many users having access to the same bastion host
- Only provide SSH access to an extremely unprivileged user
  - Reasons:
    - Prevent privilege escalation in the event the server is misconfigured
    - Force the server to be viewed as disposable and immutable so changes are version controlled and peer reviewed
- No "Temporary" changes on the host
  - Reasons:
    - No such thing as temporary
    - Everything should be peer reviewed to mitigate the unknown flaws that were never checked in
- No SSH Access to 'Wheel' Users
  - Reasons:
    - No temporary changes on host
    - No bypassing this rule through instance spawn
    - Safe by default when not spawned with cloud-init
- Offload administrative work to signing process
  - Reasons:
    - Centralizing this process allows admins to spend time focusing on critical procedures
    - Makes it easier to manage this system at scale



**Aditional Mitigations:**
- Remove cloud-init and bake CA and/or emergency access keys
  - Reasons:
    - When used in combination with AMI launch restrictions can reduce impact of lost aws creds
    - Cant override system configuration

## High Level Threats

**Externally Exposed Info:**
- Accepting network services (SSH)
- Instance host location (AWS)
- Fingerprint operating system (Amazon Linux)

**Actors:**
- Rogue Internal/External User
- Internal User

**Rouge Internal/External User:**

Detection:
- Have users report key theft
- Monitor authentication locations
- Monitor key issuance
- Monitor instance network traffic for suspicious behavior

Entry Points & Mitigations:
- Operating System vulnerability
  - Monitor CVS for OS
  - Monitor CVS for network services
  - Keep OS up to date
- OpenSSH vulnerability
  - Monitor CVS for OpenSSH
  - Keep server up to date
- Inject Keys via cloud-init and escalate privileges (Compromised AWS Credentials):
  - monitor AWS account
  - Any suspicious bastions should be terminated
- Theft of Authorized SSH Keys:
  - Short Lived Keys via authorization server
    - Minimize access time
    - Minimize number of parallel keys
    - Better audit trail
  - Hardware Crypto Tokens for SSH/PIV SSH with self destructing keys
    - Theft requires knowledge of second factor to unlock key
    - Brute force causes key to be destroyed
  - Reported/Detected Theft/Cracking
    - access to be revoked

Worst Case Capabilities:
- Acquire all capabilities of rouge internal user
- Operating System vulnerability
  - Potentially gain root access
- OpenSSH vulnerability
  - Can Enter network
  - if permissions bug; potentially gain root access
- Can control any resources trusting perimeter security
- Can bypass IP restrictions
- Privilege escalation through systems trusting network perimeter
- Can Monitor traffic passed through bastion instance
- Can inject commands into any ssh forwarding agents (acting as other users)

**Internal User:**

Restrictions:
- End System Firewall
- Network Firewalls (Security Groups)
- VPC Visibility

Uses:
- Access Internal System
- Simple authentication Proxy (locked to device)

