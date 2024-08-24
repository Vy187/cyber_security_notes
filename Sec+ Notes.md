# 1. Fundamental Security Concepts

### 1A: Security Concepts
#### Information Security
Information security (infosec) protects data resources from unauthorized access, attack, theft, or damage.
- The systems used to store, transmit, and process data must demonstrate the properties of security and that secure information has three properties called the CIA Triad:
    Three principles of security control and management. It’s known as the information security triad and referred to in reverse order as the AIC triad.
* Confidentiality means that information can only be read by people who have been authorized to access it.
* Integrity means that the data is stored and transferred as intended, and any modification is unauthorized unless explicitly authorized through proper channels.
* Availability means that information is readily accessible to those authorized to view or modify it.
Non-repudiation means that the entity that sent a transmission or modified/created data remains associated with that data and cannot deny sending/creating/modifying that data.

#### Cybersecurity Framework
Cybersecurity frameworks (CSF) are s*tandards, best practices, and guidelines for effective security risk management. Some frameworks are general, while others are specific to industry or technology types.*
Cybersecurity refers specifically to provisioning secure processing hardware and software.
- The National Institute of Standards and Technology (NIST)‘s information security and cybersecurity tasks can be classified into five functions:
    Develops computer security standards US federal agencies use and publishes cybersecurity best practice guides and research.
* Identify—develop security policies and capabilities, evaluate risks, threats, and vulnerabilities, and recommend security controls to mitigate them.
* Protect—procure/develop, install, operate, and decommission IT hardware and software assets with security as an embedded requirement of every stage of this operation's lifecycle.
* Detect—perform ongoing, proactive monitoring to ensure that controls are effective and capable of protecting against new threats.
* Respond—identify, analyze, contain, and eradicate system threats and data security.
* Recover—implement cybersecurity resilience to restore systems and data if other controls can’t prevent attacks.

#### Gap Analysis
An organization from building its security program in a vacuum, or from building the program on a foundation that fails to account for important security concepts.
A framework allows an organization to make an objective statement of its current cybersecurity capabilities, identify a target level of capability, and prioritize investments to achieve that target.
Gap analysis measures the difference between the current and desired states to help assess the scope of work included in a project.
*A gap analysis is likely to involve third-party consultants but some or all work involved with a gap analysis may be performed internally.*

#### Access Control
An access control system ensures that an information system meets the goals of the CIA triad. 
- Modern access control is typically implemented as an identity and access management (IAM) system and comprises four main processes:
    A security process that provides identification, authentication, and authorization mechanisms for users, computers, and other entities to work with organizational assets like networks, operating systems, and applications.
* Identification—the process by which a user account (and its credentials) is issued to the correct person and can be referred to as enrollment.
* Authentication—a method of validating a particular entity's or individual's unique credentials.
* Authorization—the process of determining what rights and privileges a particular entity has.
* Accounting—tracking authorized usage of a resource or use of rights by a subject and alerting when unauthorized use is detected or attempted.

### 1B: Security Controls
#### SECURITY CONTROL CATEGORIES
- A security control is designed to give a system or data asset the properties of confidentiality, integrity, availability, and non-repudiation. Controls can be divided into four broad categories based on the way the control is implemented:
    A technology or procedure to mitigate vulnerabilities and risks and confidentiality, integrity, and availability (CIA) of information.
* Managerial— the control gives oversight of the information system.
* Operational—the control is implemented primarily by people.
* Technical—the control is implemented as a system (hardware, software, or firmware). 
* Physical—controls such as security cameras, alarms, gateways, locks, lighting, and security guards that deter and detect access to premises and hardware are often placed separately from technical controls.

#### SECURITY CONTROL FUNCTIONAL TYPES
A security control can be defined according to the goal or function it performs:
* Preventive—a type of security control that acts before an incident to eliminate or reduce the likelihood that an attack can succeed.
* Detective—a type of security control that acts during an incident to identify or record that it is attempted or successful.
* Corrective—a type of security control that acts after an incident to eliminate or minimize its impact.
* Directive—a type of control that enforces a rule of behavior through a policy or contract.
* Deterrent—a type of security control that discourages intrusion attempts.
* Compensating—a security measure that takes on risk mitigation when a primary control fails or cannot completely meet expectations.
- Access control lists (ACL) configured on firewalls and file system objects are preventive-type technical controls
    The collection of access control entries (ACEs) determines which subjects (user accounts, host IP addresses, and so on) are allowed or denied access to the object and the privileges given (read-only, read/write, and so on).

#### INFORMATION SECURITY ROLES AND RESPONSIBILITIES
A Chief Information Officer (CIO) is responsible for management of information technology assets and procedures
A Chief Technology Officer (CTO) effectively uses new and emerging computing platforms and innovations.
A Chief Security Officer (CSO) or Chief Information Security Officer (CISO) is responsible for information assurance and systems security.
An Information Systems Security Officer (ISSO) has technical responsibilities for implementing security policies, frameworks, and controls.

#### INFORMATION SECURITY BUSINESS UNITS
A Security Operations Center (SOC) is a location where security professionals monitor and protect critical information assets across other business functions
Development and Operations (DevOps) is a combination of software development, security operations, and systems operations, and refers to the practice of integrating each discipline with the others.
Computer Incident Response Team (CIRT) /Computer Security Incident Response Team (CSIRT)/Computer Emergency Response Team (CERT) is a single point of contact for the notification of security incidents.

--- 

# 2. Threat Types

### 2A: Threat Actors
#### Vulnerability, Threat Actors, and Risk
Vulnerability is a weakness that could be triggered accidentally or exploited intentionally to cause a security breach.
Threat is the potential for an entity to exploit a vulnerability and breach security. A threat can have an intentional motivation or be unintentional. The person or thing that poses the threat is called a threat actor/agent*.*
Risk is the level of hazard posed by vulnerabilities and threats. When a vulnerability is identified, the risk is calculated as the likelihood of it being exploited by a threat actor and the impact that a successful exploit would have.

#### Attributes of Threat Actors
Internal/External Threat Actor refers to the degree of access a threat actor possesses before initiating an attack. An external threat actor has no standing privileges, while an internal actor has been granted some access permissions. An external actor may perpetrate an attack remotely or on-premises.
Level of sophistication/capability refers to a formal classification of the resources and expertise available to a threat actor.  At the highest level, a threat actor might use non-cyber tools such as political or military assets.
Resources/Funding refers to the ability of threat actors to draw upon funding to acquire tools and personnel and develop novel attack types.

#### Motivations Of Threat Actors
The general strategies that a threat actor could use to achieve an objective:
* Service disruption—a type of attack that compromises the availability of an asset or business process.
* Data exfiltration—the process by which an attacker takes data stored inside a private network and moves it to an external network.
* Disinformation—an attack type that falsifies an information resource normally trusted by others.
Motivation is the threat actor's reason for perpetrating the attack. The three main types of motivation for threat actors:
* Financial Motivations
- Blackmail is demanding payment to prevent the release of information.
- Extortion is demanding payment to prevent or halt an attack.
- Fraud is falsifying records.
* Chaotic Motivations
* Political Motivations

#### Hackers and Hacktivists
Hacker refers to someone who breaks into computer systems or spreads viruses, ethical hackers prefer to think of themselves as experts on and explorers of computer security systems.
- Black Hat is an unauthorized hacker operating with malicious intent.
- White Hat is an authorized hacker engaged in penetration testing or other security consultancy.
An unskilled attacker is someone who uses hacker tools without necessarily understanding how they work or having the ability to craft new attacks.
A hacktivist is a threat actor motivated by a social issue or political cause.

#### Nation-State Actors
A nation-state actor is a threat actor supported by the resources of its host country's military and security services.
Advanced Persistent Threat (APT) refers to an attacker's ability to obtain, maintain, and diversify access to network systems using exploits and malware.

#### Organized Crime and Competitors
Organized crime is a threat actor that uses hacking and computer fraud for commercial gain.

#### Internal Threat Actors
Internal threat is a type of threat actor assigned privileges on the system that cause an intentional or unintentional incident.
*A* whistleblower *is someone with an ethical motivation for releasing confidential information.*
An unintentional or inadvertent insider threat is a threat actor that causes a vulnerability or exposes an attack vector without malicious intent.
Shadow IT is computer hardware, software, or services used on a private network without authorization from the system owner.
### 2B: Attack Surfaces

#### Attack Surface and Threat Vectors
The attack surface is all the points at which a malicious threat actor could try to exploit a vulnerability. Any location or method where a threat actor can interact with a network port, app, computer, or user is part of a potential attack surface.
A threat vector is a specific path by which a threat actor gains unauthorized access to a system.

#### Vulnerable Software Vectors
Vulnerable software contains a flaw in its code or design that can be exploited to circumvent access control or to crash the process.
- Unsupported systems and applications are reasons that vulnerable software will be exposed as a threat vector.
    Product life cycle phase where mainstream vendor support is no longer available.
A strategy for dealing with unsupported apps that cannot be replaced is to isolate them from other systems.

#### Network Vectors
An exploit technique for any software vulnerability can be classed as remote or local.
- An unsecured network lacks the attributes of confidentiality, integrity, and availability. Threat vectors associated with unsecured networks:
    A configuration that exposes a large attack surface, such as through unnecessary open service ports, weak or no authentication, use of default credentials, or lack of secure communications/encryption.
* Direct Access
* Wired Network
* Remote and Wireless Network
* Cloud Access
* Bluetooth Network
* Default Credentials
* Open Service Port

#### Lure-Baed Vectors
- A lure is something superficially attractive or interesting that causes its target to want it. Commonly used as lures:
    An attack type that will entice a victim into using or opening a removable device, document, image, or program that conceals malware.
* Removable Device
* Executable File
* Document Files
* Image Files

#### Message-Based Vectors
In a file-based lure, the threat actor needs a mechanism to deliver the file and a message will trick a user into opening the file on their computer. The main types of a file-based lure:
* Email
* Short Message Service (SMS)
* Instant Messaging (IM)
* Web and Social Media
Zero-click means receiving an attachment or viewing an image on a webpage triggering the exploit.

#### Supply Chain Attack Surface
A supply chain is the end-to-end process of designing, manufacturing, and distributing goods and services for a customer. The types of procurement management relationships:
* Supplier
* Vendor
* Business Partner

### 2C: Social Engineering
#### Human Vectors
Social engineering is an activity where the goal is to use deception and trickery to convince unsuspecting users to provide sensitive data or to violate security guidelines.

#### Impersonation and Pretexting
Impersonation is a social engineering attack where an attacker pretends to be someone they are not. There are two approaches to this attack:
* Persuasive/consensus/liking
* Coercion/threat/urgency

#### Phishing and Pharming
Phishing is an email-based social engineering attack, in which the attacker sends an email from a supposedly reputable source to elicit private information from the victim.
Vishing is a human-based attack where the attacker extracts information while speaking over the phone or leveraging IP-based voice messaging services (VoIP).
SMiShing is a form of phishing that uses SMS text messages to trick a victim into revealing information.
Pharming is an impersonation attack in which a request for a website is redirected to a similar-looking, but fake, website.

#### Typosquatting
Typosquatting is an attack in which an attacker registers a domain name with a common misspelling of an existing domain so that a user who misspells a URL they enter into a browser is taken to the attacker's website. These are also referred to as cousin, lookalike, or doppelganger domains.

#### Business Email Compromise
Business email compromise refers to an impersonation attack in which the attacker gains control of an employee's account and uses it to convince other employees to perform fraudulent actions.
Brand impersonation means the threat actor commits resources to accurately duplicate a company's logos and formatting to make a phishing message or pharming website, a visually compelling fake.
A watering hole attack is when an attacker targets specific groups or organizations, discovers which websites they frequent, and injects malicious code into those sites.

---

# 3. Cryptographic Solutions

### 3A: Cryptographic Algorithms
#### Cryptographic Concepts
Cryptography is the science and practice of altering data to make it unintelligible to unauthorized parties. The  terminology is used to discuss cryptography:
* Plaintext (*cleartext*)—unencrypted data meant to be encrypted before it is transmitted, or the result of decryption of encrypted data.
* Ciphertext—data that has been enciphered and cannot be read without the cipher key.
* Algorithm—operations that transform plaintext into a ciphertext with cryptographic properties, also called a cipher. There are symmetric, asymmetric, and hash cipher types.
* Cryptanalysis—the science, art, and practice of breaking codes and ciphers.

#### Symmetric Encryption
Encryption scrambles the characters used in a message so that the message can be seen but difficult to read or modify unless it is deciphered. It provides a secure means of transmitting data and authenticating users. It is used to store data securely. It uses different types of cipher and one or more keys. The size of the key is one factor in determining the strength of the encryption product. Using a key with the encryption cipher ensures that decryption can only be performed by an authorized person.
Symmetric encryption is a two-way encryption scheme in which encryption and decryption are performed with the same key. This is also known as shared-key encryption.

#### Key Length
The key length refers to the size of a cryptographic key in bits. Longer keys generally offer better security, but key lengths for different ciphers are not directly comparable.

#### Asymmetric Encryption
Asymmetric encryption uses a cipher that uses public and private keys. The keys are mathematically linked, using either Rivel, Shamir, Adleman (RSA) or elliptic curve cryptography (ECC) algorithms, but the private key is not derivable from the public one. An asymmetric key cannot reverse the operation, so the public key cannot decrypt what it has encrypted.
The public key is freely distributed and performs the reverse encryption or decryption operation of the linked private key in the pair. 
The private key is known only to the holder and is linked to, but not derivable from, a public key distributed to those with whom the holder wants to communicate securely. A private key encrypts data that can be decrypted by the linked public key or vice versa.

#### Hashing
Hashing is a function that converts an arbitrary-length string input to a fixed-length string output. A cryptographic hash function does this in a way that reduces the chance of collisions, where two different inputs produce the same output. The implementations of hash algorithms:
* Secure Hash Algorithm (SHA) is a cryptographic hashing algorithm created to address possible weaknesses in MDA. The current version is SHA-2.
* Message Digest Algorithm #5 (MD5) is a cryptographic hash function producing a 128-bit output.

#### Digital Signatures
Cryptographic primitive refers to a single hash function, symmetric cipher, or asymmetric cipher.
A digital signature is a message digest encrypted using the sender's private key appended to a message to authenticate the sender and prove message integrity.

### 3B: Public Key Infrastructure
#### Certificate Authorities
Public key infrastructure (PKI) refers to a framework of certificate authorities, digital certificates, software, services, and other cryptographic components deployed to validate subject identities. Under PKI, anyone issuing a public key should publish it in a digital certificate. 
A Certificate authority (CA) is a server that guarantees subject identities by issuing signed digital certificate wrappers for their public keys.
In PKI, a third-party CA is a public CA that issues certificates for multiple domains and is widely trusted as a root trust by operating systems and browsers.

#### Digital Certificates
A digital certificate identification and authentication information presented in the X.509 format and issued by a certificate authority (CA) as a guarantee that a key pair (as identified by the public key embedded in the certificate) is valid for a particular subject (user or host).

#### Root of Trust
The Root of Trust model defines how users and different CAs can trust one another
In PKI, a root certificate is a CA that issues certificates to intermediate CAs in a hierarchical structure.
A certificate chaining or a chain of trust is a method of validating a certificate by tracing each CA that signs the certificate, up through the hierarchy to the root CA.
A self-signed certificate is a digital certificate signed by the entity that issued it, rather than by a CA.

#### Certificate Signing Requests
A certificate signing request (CSR) is a Base64 ASCII file that a subject sends to a CA to get a certificate.

#### Subject Name Attributes
A subject alternative name (SAN) is a field in a digital certificate allowing a host to be identified by multiple hostnames/subdomains.
In PKI, a wildcard domain is a digital certificate that matches multiple parent domain subdomains.
A certificate also contains fields for Organization (O), Organizational Unit (OU), Locality (L), State (ST), and Country (C).

#### Certificate Revocation
A certificate revocation list (CRL) is a list of certificates revoked before expiration and 
has the following attributes:
* Publish Period
* Distribution Point(s)
* Validity Period
* Signature
The certificate may be revoked but still accepted by clients because an up-to-date CRL has yet to be published. The browser (or other application) may not be configured to perform CRL checking.
An Online Certificate Status Protocol (OCSP) server allows clients to request the status of a digital certificate, to check whether it is revoked.

#### Key Management
Key management refers to operational considerations for the various stages in a key's lifecycle. A key's lifecycle:
* Key Generation
* Storage
* Revocation
* Expiration and Renewal
In PKI, a key management system contains procedures and tools that centralize the generation and storage of cryptographic keys.

#### Cryptoprocessors and Secure Enclaves
Entropy is a measure of disorder. Cryptographic systems should exhibit high entropy for better resistance to brute-force attacks.
Pseudo RNG (PRNG) is the process by which an algorithm produces numbers that approximate randomness without being truly random.
True RNG (TRNG) generates random values by sampling physical phenomena with a high entropy.
The two main ways of implementing cryptoprocessor hardware are TPMs and HSMs.
A Trusted Platform Module (TPM) is a specification for secure hardware-based storage of encryption keys, hashed passwords, and other user- and platform-identification information. The three principal ways of implementing a TPM:
* Discrete
* Integrated
* Firmware
A virtual TPM can be implemented in a hypervisor to provide a service to virtual machines (VMs).
A Hardware security module (HSM) is an appliance for generating and storing cryptographic keys. This solution may be less susceptible to tampering and insider threats than software-based storage.
An Application Programming Interface (API) allows methods exposed by a script or program other scripts or programs to use.
A secure enclave is a CPU extensions that protect data stored in system memory so that an untrusted process cannot read it.

#### Key Escrow
In key management, escrow refers to the backup key storage with a third party.
An account with permission to access a key held in escrow is referred to as a key recovery agent (KRA).

### 3C: Cryptographic Solutions
#### Encryption Supporting Confidentiality
Data can be described as being in one of three states:
* Data at rest—information that is primarily stored on specific media.
* Data in transit (data in motion)—information transmitted between two hosts.
* Data in use (data in processing)—information in volatile memory of a host.

#### Disk and File Encryption
Encryption levels refer to the target for data-at-rest encryption, ranging from more granular (file or row/record) to less granular (volume/partition/disk or database).
Full-disk encryption (FDE) refers to a product that encrypts the whole contents of a storage device, including metadata areas not normally accessible using ordinary OS file explorer tools.
A self-encrypting drive (SED) could be a hard disk drive (HDD), solid-state drive (SSD), or USB flash drive.
A volume is any storage resource with a single file system.
A file encryption product is software that applies encryption to individual files (or perhaps to folders/directories).
Metadata can include a list of files, the file owner, and created/last modified dates. Free or unallocated space can contain data remnants, where a file has been marked as deleted, but the data has not been erased from the storage medium.

#### Database Encryption
The table data is ultimately stored as files on a volume, but access is designed to be mediated through a database management system (DBMS) running a database language.
Transparent Data Encryption (TDE) encrypts records while stored on disk, protecting against theft of the underlying media.
Record-level encryption refers to cell/column encryption applied to one or more fields within a table.

#### Transport Encryption and Key Exchange
Transport/communication encryption is an encryption scheme for data-in-motion, such as WPA, IPsec, or TLS.
Hash-based Message Authentication Code (HMAC) is a method used to verify the integrity and authenticity of a message by combining a cryptographic hash of the message with a secret key.
The symmetric cipher might be designed to perform Authenticated Encryption (AE)

#### Perfect Forward Secrecy
- Perfect Forward Secrecy (PFS) is a characteristic of transport encryption that ensures if a key is compromised, the compromise will only affect a single session and not facilitate recovery of plaintext data from other sessions. PFS uses Diffie-Hellman (D-H) key agreement to create ephemeral session keys without using the server's private key.
    In cryptography, a key is used within the context of a single session only.
PFS is now more usually implemented as Elliptic Curve DHE (ECDHE).

#### Salting and Key Stretching
Salting is a security countermeasure that mitigates the impact of precomputed hash table attacks by adding a random value to ("salting") each plaintext input.
Key Stretching is a technique that strengthens potentially weak input for cryptographic key generation, such as passwords or passphrases created by people, against brute force attacks.

#### Blockchain
Blockchain is a concept in which an expanding list of transactional records listed in a public ledger is secured using cryptography.
An open public ledger is a distributed public record of transactions that underpins the integrity of blockchains

#### Obfuscation
Obfuscation is a technique that essentially "hides" or "camouflages" code or other information so unauthorized users it is harder to read. The three main techniques:
* Steganography is a technique for obscuring the presence of a message, often by embedding information within a file or other entity.
* Data masking is an ade-identification method where generic or placeholder labels are substituted for real data while preserving the structure or format of the original data.
* Tokenization is a de-identification method where a unique token is substituted for real data.

---

# 4. Identity and Access Management

### 4A: Authentication
#### Authentication Design
Authentication is performed when a supplicant or claimant presents credentials to an authentication server.
In authentication design, the different technologies factors for implementing authentication, such as knowledge, ownership/token, and biometric/inherence. These are characterized as something you know/have/are.
A Personal Identification Number (PIN) is a number used in conjunction with authentication devices such as smart cards; as the PIN should be known only to the user, loss of the smart card should not represent a security risk.

#### Password Concepts
- Password best practices refer to rules to govern the secure selection and maintenance of knowledge factor authentication secrets, such as length, complexity, age, and reuse. To supplement best practice awareness, system-enforced account policies can help to enforce credential management principles by stipulating requirements for user-selected passwords:
    A set of rules governing user security information which can be set globally.
* Password Length
* Password Complexity
* Password Age
* Password Reuse and History

#### Password Managers
A password manager is software that suggests and stores site and app passwords to reduce risks from poor user choices and behavior. Most browsers have a built-in password manager.

#### Multifactor Authentication
A multifactor authentication (MFA) is an authentication scheme that requires the user to present at least two different factors as credentials; These factors are “something you know”, “something you have”, “something you are”, “something you do”, and “somewhere you are”.

#### Biometric Authentication
Biometric authentication is an authentication mechanism that allows users to perform a biometric scan to operate an entry or access system. Physical characteristics stored as a digital data template can be used to authenticate a user.
The efficacy rate of biometric pattern acquisition and matching and suitability as an authentication mechanism can be evaluated using the following metrics and factors:
* False Rejection Rate (FRR)—a biometric assessment metric measuring the number of valid subjects with denied access. This is a Type I error or false non-match rate (FNMR). FRR is measured as a percentage.
* False Acceptance Rate (FAR)—a biometric assessment metric that measures the number of unauthorized users who are mistakenly allowed access. This is a Type II error or false non-match rate (FNMR). FAR is measured as a percentage.
* Crossover Error Rate (CER)—a biometric evaluation factor expressing the point at which FAR and FRR meet, with a low value indicating better performance.
* Throughput (speed)—the time required to create a template for each user and the time required to authenticate.
* Failure to Enroll Rate (FER)—incidents in which a template cannot be created and matched for a user during enrollment.
* Cost/Implementation
* Users can find it intrusive and threatening to privacy.
* Users can find it intrusive and threatening to privacy.
* The technology can be discriminatory or inaccessible to those with disabilities.

#### Hard Authentication Tokens
There are three main types of token generation:
* Certificate-Based Authentication
* One-Time Password (OTP)
* Fast Identity Online (FIDO) Universal 2nd Factor (U2F)
A cryptoprocessor on a dedicated hardware device generates a hard authentication token. As the token is never transmitted directly, this implements an ownership factor within a multifactor authentication scheme. Device-based authenticators can be used to implement hard tokens:
* Smart cards—a security device similar to a credit card that can store authentication information.
* One-time password (OTP)—a password generated for use in one specific session and becomes invalid after the session ends.
* Security key—portable HSM with a computer interface, such as USB or NFC, used for multifactor authentication.

#### Soft Authentication Tokens
A soft authentication token is an OTP sent to a registered number or email account or generated by an authenticator app to verify two-step account access. Soft tokens sent via SMS or email are not an ownership factor.

#### Passwordless Authentication
Passwordless is a multifactor authentication scheme that uses ownership and biometric factors, and no knowledge factors.
Attestation is the capability of an authenticator or other cryptographic module to prove that it is a root of trust and can provide reliable reporting to prove that a device or computer is a trustworthy platform.

### 4B: Authorization
#### Discretionary and Mandatory Access Control
Permissions refer to security settings that control access to objects including file system items and network resources.
An access control model describes the principles that govern how users receive rights.
Discretionary Access Control (DAC) is an access control model where each resource is protected by an access control list (ACL) managed by the resource's owner (or owners).
Mandatory Access Control (MAC) is an access control model where an inflexible, system-defined rule protects the resources. Resources (objects) and users (subjects) are allocated a clearance level (or label).

#### Role and Attribute Based Access Control
Role-Based Access Control (RBAC) is an access control model where resources are protected by ACLs that are managed by administrators and that provide user permissions based on job functions.
A group account is a collection of useful user accounts when establishing file permissions and user rights because many individuals will need the same level of access, a group is then established containing all the relevant users.
Attribute-Based Access Control (ABAC) is an access control technique that evaluates a set of attributes that a subject possesses to determine if access should be granted.

#### Rule-Based Access Control
Rule-based access control is a nondiscretionary access control technique based on operational rules or restrictions to enforce a least privileges permissions policy.

#### Least Privilege Permission Assignments
Least Privilege is a basic principle of security stating that something should be allocated the minimum necessary rights, privileges, or information to perform its role.

#### User Account Provisioning
Provisioning is deploying an account, host, or application to a target production environment. This involves proving the identity or integrity of the resource and issuing it with credentials and access permissions. Provisioning a user account involves:
* Identity Proofing
* Issuing Credentials
* Issuing Hardware and Software Assets
* Teaching Policy Awareness
* Creating Permissions Assignment
Deprovisioning is the process of removing an account, host, or application from the production environment. This requires revoking any privileged access that had been assigned to the object.

#### Account Attributes and Access Policies
Security Identifier (SID) refers to the value assigned to an account by Windows and used by the operating system to identify that account.
On a Windows domain, Group Policy Objects (GPOs) deploy per-user and per-computer settings such as password policy, account restrictions, firewall status, etc.

#### Account Restrictions
- The geographical location of a user or device can be calculated using a geolocation mechanism:
    The identification or estimation of the physical location of an object, such as a radar source, mobile phone, or Internet-connected computing device.
* IP address
* Location Services
There are four main types of time-based policies:
* Time-of-day restrictions—policies or configuration settings that limit a user's access to resources.
* Duration-based login policy
* Impossible travel time/risky login policy
* Temporary permissions policy

#### Privileged Access Management
Privileged Access Management (PAM) refers to policies, procedures, and support software for managing accounts and credentials with administrative permissions.
Just-in-time (JIT) permissions means that an account's elevated privileges are not assigned at log-in. Zero Standing Privileges (ZSP) permissions must be explicitly requested and are only granted for a limited period. The  three main models for ZSP:
* Temporary Elevation
* Password Vaulting/Brokering—M of N control refers to the control that requires multiple people for authentication.
* Ephemeral Credentials

### 4C: Identity Management
#### Local, Network, and Remote Authentication
An authentication provider is the software architecture and code that underpins the mechanism where the user is authenticated before starting a shell. Windows authentication involves a complex architecture of components. These three scenarios are typical:
* Windows local sign-in
* Windows network sign-in
* Remote sign-in
A pluggable authentication module (PAM) is a framework for implementing authentication providers in Linux.

#### Directory Services
A directory service is a network service that stores identity information about all the objects in a particular network, including users, groups, servers, client computers, and printers.
Lightweight Directory Access Protocol (LDAP) is a protocol used to access network directory databases that store information about authorized users and the users’ privileges and organizational information.
A distinguished name (DN) is a collection of attributes defining a unique identifier for any given resource within an X.500-like directory. Common attributes used: Common Name (CN), Organizational Unit (OU), Organization (O), Country (C), and Domain Component (DC).

#### Single Sign-on Authentication
A Single Sign-On (SSO) is an authentication technology that authenticates users once and receives authorizations for multiple services.
Kerberos is a single sign-on authentication and authorization service based on a time-sensitive, ticket-granting system.
A Key Distribution Center (KDC) is a component of Kerberos that authenticates users and issues tickets (tokens).
In Kerberos, a Ticket Granting Ticket (TGT) issues a token to an authenticated account to allow access to authorized application servers. (TGT)—contains information about the client (name and IP address) plus a time stamp and validity period. This is encrypted using the KDC's secret key.
TGS session key—communicates between the client and the Ticket Granting Service (TGS). This is encrypted using a hash of the user's password.

#### Federation
A federation is a process that provides a shared login capability across multiple systems and enterprises. It connects the identity management services to systems.
In a federated network, the Identity Provider (IdP) is the service that holds the user account and performs authentication.

#### Security Assertion Markup language
A Security Assertion Markup Language (SAML) is an XML-based data format to exchange authentication information between a client and a service.
A Simple Object Access Protocol (SOAP) is an XML-based web services protocol to exchange messages.

#### Open Authorization
Representational State Transfer (REST) is a standardized, stateless architectural style for web applications for communication and integration.
Open Authorization is a standard for federated identity management, allowing resource servers or consumer sites to work with user accounts created and managed on a separate identity provider.
Javascript Object Notation (JSON) is a file format that uses attribute-value pairs to define configurations in a structure that is easy for humans and machines to read and consume.

---

# 5. Secure Enterprise Network Architecture

### 5A: Architecture
#### Architecture and Infrastructure Concepts
Network architecture means the selection and placement of media, devices, protocols/services, and data assets:
* Network infrastructure is the media, appliances, and addressing/forwarding protocols that support basic connectivity.
* Network applications are the services that run on the infrastructure to support business activities, such as processing invoices or sending emails.
* Data assets are the information created, stored, and transferred as business activity.
A workflow is a series of tasks that a business needs to perform.

#### Switching Infrastructure Considerations
An on-premises network is a private network facility owned and operated by an organization for use by its employees only.

#### Routing Infrastructure Considerations
Logical Segmentation refers to network topology enforced by switch, router, and firewall configuration where hosts on one network segment are prevented from or restricted in communicating with hosts on other segments.
Internet Protocol (IP) refers to the Network (Internet) layer protocol in the TCP/IP suite providing packet addressing and routing for all higher-level protocols in the network.
A Virtual LAN (VLAN) is a logical network segment comprising a broadcast domain established using a feature of managed switches to assign each port a VLAN ID. Even though hosts on two VLANs may be physically connected to the same switch, local traffic is isolated to each VLAN, so they must use a router to communicate.

#### Security Zones
To map out the internal security topology, analyze the systems and data assets that support workflows and identify ones that have similar access control requirements:
* Database and file systems host company data and personal data should prioritize confidentiality and integrity.
* Client devices need to prioritize integrity and availability.
* Public-facing application servers (web, email, remote access, and so on) should also prioritize integrity and availability.
* Application servers that support the network infrastructure (authentication, directory, and monitoring/logging, for example) must exhibit high confidentiality, integrity, and availability.
A security zone is an area of the network (connected network) where the security configuration is the same for all hosts. In physical security, an area is separated by barriers that control entry and exit points. A zone must have a known entry and exit point.

#### Attack Surface
Attack surface refers to the points at which a network or application receives external connections or inputs/outputs that are potential vectors to be exploited by a threat actor. The layer model to analyze the potential attack surface:
* Layer 1/2—allows unauthorized hosts to connect to wall ports or wireless networks and communicate with hosts within the same broadcast domain.
* Layer 3—allows unauthorized hosts to obtain a valid network address, possibly by spoofing, and communicate with hosts in other zones
* Layer 4/7—allows unauthorized hosts to establish connections to TCP or UDP ports and communicate with application layer protocols and services.
Weaknesses in the network architecture make it more susceptible to undetected intrusions or catastrophic service failures:
* Single points of failure
* Complex dependencies
* Availability in exchange for confidentiality and integrity
* Lack of documentation and change control
* Overdependence on perimeter security

#### Port Security
Port security prevents a device attached to a switch port from communicating on the network unless it matches a given MAC address or other protection profile.
MAC filtering applies an access control list to a switch or access point so clients with approved MAC addresses can connect.
IEEE 802.1X is a standard for encapsulating EAP communications over a LAN (EAPoL) or WLAN (EAPoW) to implement port-based authentication. 802.1X uses authentication, authorization, and accounting (AAA) architecture:
* Supplicant—in EAP architecture, the device requesting access to the network.
* Authenticator—a PNAC switch or router that activates EAPoL and passes a supplicant's authentication data to an authenticating server, such as a RADIUS server.
* Authentication Server—the server that holds or can contact a directory of network objects and validate authentication requests, issue authorizations, and perform accounting of security events.
Two protocols are implemented in the 802.1X standard:
* Extensible Authentication Protocol (EAP)—a framework for negotiating authentication methods that enable systems to use hardware-based identifiers, such as fingerprint scanners or smart card readers, authentication and to establish secure tunnels through which to submit credentials.
* Remote Authentication Dial-In User Service (RADIUS)—AAA protocol used to manage remote and wireless authentication infrastructures.

#### Physical Isolation
Air-gapped refers to network isolation that physically separates a host from other hosts or a network from all other networks.

#### Architecture Considerations
When evaluating the use of a particular architecture and selecting effective controls, consider several factors:
* Cost
* Compute and Responsiveness
* Scalability
* Availability
* Resilience and Ease of Recovery
* Power
* Patch Availability
* Risk Transference

### 5B: Network Security Appliances
#### Device Placement
Selection of effective controls refers to choosing the type and placement of security controls to ensure the goals of the CIA triad and compliance with any framework requirements.
Defense in depth is a security strategy that positions the layers of diverse security control categories and functions as to relying on perimeter controls.
Device placement refers to considerations for positioning security controls to protect network zones and individual hosts to implement a defense-in-depth strategy and to meet overall security goals. There are three options:
* Preventive controls
* Detective controls
* Corrective controls

#### Device Attributes
A passive security control is an enumeration, vulnerability, or incident detection scan that analyzes only intercepted network traffic rather than sending probes to a target. More generally, passive reconnaissance techniques do not require direct interaction with the target.
Active security control refers to detective and preventive security controls that use an agent or network configuration to monitor hosts. This allows for more accurate credentialed scanning, but consumes some host resources and is detectable by threat actors.
Inline refers to the placement and configuration of a network security control so that it becomes part of the cable path.
A sensor is a monitor that records (or "sniffs") data from frames as they pass over network media, using methods such as a mirror port or TAP device. A sensor can be configured to receive traffic in two different ways:
* Test access point (TAP)—a hardware device inserted into a cable run to copy frames for analysis.
* SPAN (switched port analyzer)/mirror port—copying ingress and or egress communications from one or more switch ports to another port. This is used to monitor communications passing over the switch.
When a  security device fails, a device can be designed or configured to:
* Fail-open is a security control configuration that ensures continued access to the resource in the event of failure.
* Fail-closed is a security control configuration that blocks access to a resource in the event of failure.

#### Firewalls
A packet filtering firewall is a Layer 3 firewall technology that compares packet headers against ACLs to determine which network traffic to accept. The rules are based on the information found in those headers:
* IP filtering—accepts or denies traffic based on bits source or IP address destination or does both.
* Protocol ID/type—an IP packet carrying an identified protocol.
* Port filtering/security—accepts or denies a packet based on the source and destination TCP/UDP port numbers.
An appliance firewall is a standalone hardware device that performs only the function of a firewall, which is embedded into the appliance's firmware and deployed in three ways:
* Routed (layer 3)—the firewall performs forwarding between subnets.
* Bridged (layer 2)—the firewall inspects traffic between two nodes.
* Inline (layer 1)—the firewall acts as a cable segment.
A router firewall or firewall router appliance is a hardware device with the primary function of a router but has firewall functionality embedded into the router firmware.

#### Layer 4 and Layer 7 Firewalls
A stateful inspection is a technique used in firewalls to analyze packets down to the application layer rather than filtering packets only by header information, enabling the firewall to enforce tighter and more security.
A state table has information about sessions between hosts gathered by a stateful firewall.
A layer 4 firewall is a stateful inspection firewall that can monitor TCP sessions and UDP traffic.
A layer 7 firewall is a stateful inspection firewall that can filter traffic based on specific application protocol headers and data, such as web or email data.

#### Proxy Servers
- A proxy server is a server that mediates the communications between a client and another server. It can filter and modify communications and provide caching services to improve performance. Proxy servers can be classed as non-transparent or transparent (or forced or intercepting).
    A non-transparent proxy server that redirects requests and responses for clients configured with the proxy address and port. 
    A transparent proxy server that redirects requests and responses without the client being explicitly configured to use it.
A reverse proxy server protects servers from direct contact with client requests.
A caching engine is a feature of many proxy servers that enables the servers to retain a copy of frequently requested web pages. Proxy Auto-Configuration (PAC) script to configure proxy settings without user intervention. The Web Proxy Auto-Discovery (WPAD) protocol enables browsers to locate a PAC file.

#### Intrusion Detections Systems
An Intrusion Detection System (IDS) is a security appliance or software that analyzes data to identify traffic that violates policies or rules from a packet sniffer.
An Intrusion Prevention System (IPS) is a security appliance or software with detection capabilities and functions that can actively block attacks. An IPS scans traffic to match detection signatures and can be configured to stop an attack automatically:
* Shunning—block the source of the noncompliant traffic, either temporarily or permanently.
* Reset the connection but do not block the source address.
* Redirect traffic to a honeypot or honeynet for additional threat analysis.

#### Next-Generation Firewalls and Unified Threat Management
A next-generation firewall is an advanced firewall technology with the following features:
* Layer 7 application-aware filtering, including inspection of Transport Layer Security (TLS) encrypted traffic.
* Integration with network directories, facilitating per-user or per-role content and time-based filtering policies, providing better protection against an insider threat.
* Intrusion prevention system (IPS) functionality.
* Integration with cloud networking.
Unified Threat Management (UTM) is an all-in-one security appliance and agent that combines the functions of a firewall, malware scanner, intrusion detection, vulnerability scanner, data-loss prevention, content filtering, and so on.

#### Load Balancers
A load balancer is a switch, router, or software that distributes client requests between different resources, such as communications links or similarly configured servers. This provides fault tolerance and improves throughput. There are two main types of load balancers:
* Layer 4 load balancer—basic load balancers make forwarding decisions on IP address and TCP/UDP port values, working at the transport layer of the OSI model.
* Layer 7 load balancer (content switch)—make forwarding decisions based on application-level data
The scheduling algorithm is the code and metrics determining which node is selected for processing each incoming request.
Session affinity is a scheduling approach that load balancers use to route traffic to devices that have already established connections with the client.
In load balancing, persistence is the configuration option that enables a client to maintain a connection with a load-balanced server over the session duration and is referred to as sticky sessions.

#### Web Application Firewalls
A Web Application Firewall (WAF) is a firewall designed to protect software running on web servers and their back-end databases from code injection and DoS attacks.

### 5C: Secure Communications
#### Remote Access Architecture
Remote access refers to the infrastructure, protocols, and software that allow a host to join a local network from a physically remote location or a session on a host to be established over a network.
A Virtual Private Network (VPN) is a secure tunnel between two endpoints connected via an unsecured transport network (typically the Internet).
A host-to-host tunnel secures traffic between two computers where the private network is not trusted.
Cisco and Microsoft developed the Point-to-Point Tunneling Protocol (PPTP) to support VPNs over PPP and TCP/IP. PPTP is highly vulnerable to password-cracking attacks and is considered obsolete.

#### Transport Layer Security Tunneling
Transport Layer Security (TLS) VPN is a virtual private networking solution that uses digital certificates to identify, host, and establish secure tunnels for network traffic.
A TLS VPN can use either TCP or UDP. UDP might be chosen for marginally superior performance, especially when tunneling latency-sensitive traffic such as voice or video. 

#### Internet Protocol Security Tunneling
Internet Protocol Security (IPsec) is a network protocol suite used to secure data through authentication and encryption as the data travels across the network or the Internet. The two core protocols in IPsec:
* Authentication Header (AH)—performs a cryptographic hash on the whole packet, including the IP header, plus a shared secret key (known only to the communicating hosts), and adds this value in its header as an Integrity Check Value (ICV).
* Encapsulating Security Payload (ESP)—used to encrypt the packet rather than simply calculating an ICV.
IPsec can be used in two modes:
* Transport mode—used to secure communications between hosts on a private network.
* Tunnel mode—used for communications between VPN sites across an unsecured network.

#### Internet Key Exchange
The Internet Key Exchange (IKE) is a framework for creating a security association (SA) used with IPSec. An SA establishes that two hosts trust one another (authenticate) and agree on secure protocols and cipher suites to exchange data. IKE negotiations have two phases:
1. Phase I establishes the identity of the two peers and performs key agreement using the Diffie-Hellman algorithm to create a secure channel. Two methods of authenticating peers are commonly used:
    - Digital certificates
    - Pre-shared key (group authentication)
2. Phase II uses the secure channel created in Phase I to establish which ciphers and key sizes will be used with AH and or ESP in the IP sec session.

#### Remote Desktop
Remote Desktop Protocol (RDP) is an application protocol for operating remote connections to a host using a graphical interface. The protocol sends screen data from the remote host to the client and transfers mouse and keyboard input to the remote host. It uses TCP port 3389.
Virtual Network Computing (VNC) is a remote access tool and protocol. VNC is the basis of macOS screen sharing.
HTML5 VPN uses features of HTML5 to implement remote desktop/VPN connections via browser software (clientless).

#### Secure Shell
Secure Shell (SSH) is an application protocol supporting secure tunneling, remote terminal emulation, and file copy. SSH runs over TCP port 22.
SSH methods for the client to authenticate to the server while using the /etc/ssh/sshd_config file:
* Username/password
* Public key authentication
* Kerberos

#### Out-of-band management and Jump Servers
Out-of-band (OOB) accesses the administrative interface of a network appliance using a separate network from the usual data network.
A single administration server or jump server is a hardened server that provides access to other hosts.

---

# 6. Secure Cloud Network Architecture

### 6A: Cloud Infrastructure
#### Cloud Deployment Models
A cloud deployment model classifies the ownership and management of a cloud as public, private, community, or hybrid and can be broadly categorized as:
- * Public (multi-tenant)—is a service offered over the Internet by Cloud Service Providers (CSPs) to cloud consumers. With this model, businesses can offer subscriptions or pay-as-you-go financing while providing lower-tier services free of charge. As a shared resource, there are risks regarding performance and security. Multi-cloud architectures are where an organization uses services from multiple CSPs.
    The public (multi-tenant) model is a cloud deployment for shared use by multiple independent tenants.
    Cloud Service Provider (CSP) refers to an organization providing infrastructure, application, and or storage services via an "as a service" subscription-based, cloud-centric offering.
    Multi-cloud is a cloud deployment model where the cloud consumer uses multiple public cloud services.
- * Hosted Private—hosted by a third party and completely private to and owned by the organization. This is more secure and can guarantee better performance but be more expensive. With private cloud computing, organizations exercise greater control over the privacy and security of their services.
    The private model is a cloud deployment used by a single entity.
    Cloud computing is a computing architecture where on-demand resources provisioned with high availability, scalability, and elasticity are billed to customers based on metered utilization.
- * Community—is where several organizations share the costs of a hosted private or fully private cloud.
    The Community model is a cloud deployment for shared use by cooperating tenants.
Different cloud architecture models have varying security implications:
* Single-tenant architecture—a dedicated infrastructure to a single customer, ensuring that only that customer can access the infrastructure. T\It offers the highest level of security as the customer has complete control over the infrastructure. However, it can be more expensive than multi-tenant architecture, and the customer is responsible for managing and securing the infrastructure.
* Multi-tenant architecture—multiple customers share the same infrastructure, with each customer's data and applications separated logically from other customers. This is cost-effective but can increase the risk of unauthorized access or data leakage if not properly secured.
* Hybrid architecture—uses public and private cloud infrastructure. This model provides greater flexibility and control over sensitive data and applications by allowing customers to store sensitive data on private cloud infrastructure while using public cloud infrastructure for less sensitive workloads. However, it also requires careful management to ensure proper integration and security between the public and private clouds.
* Serverless architecture—the cloud provider manages the infrastructure and automatically scales resources up or down based on demand. This model can be more secure than traditional architectures because the cloud provider manages and secures the infrastructure. However, customers must still take steps to access their applications and data securely

#### Cloud Service Models
Anything as a Service (Xaas) is the concept that most types of IT requirements can be deployed as a cloud service model and the three implementations of it:
* Software as a Service (SaaS) is a cloud service model that supplies fully developed application services to users.
* Platform as a Service (PaaS) is a cloud service model that provisions application and database services as a platform for the development of apps.
* Infrastructure as a Service (IaaS) is a cloud service model that provisions virtual machines and network infrastructure.
Third-party vendors are external entities that provide organizations with goods, services, or technology solutions.

#### Responsibility Matrix
A responsibility matrix identifies responsibility for security as applications, data, and workloads are transitioned into a cloud platform and are shared between the customer and the cloud service provider (CSP). It sets out these duties in a clear, tabular format too.

#### Centralized and Decentralized Computing
A centralized computing architecture is a model where all data processing and storage is performed in a single location.
A decentralized computing architecture is a model in which data processing and storage are distributed across multiple locations or devices. Some examples of decentralized architecture are the blockchain, Peer-to-Peer (P2P), Content Delivery Network (CDN), Internet of Things (IoT), distributed databases, and The Onion Router (TOR).

#### Resilient Architecture Concepts
Virtualization is a computing environment where multiple independent operating systems can be installed on a single hardware platform and run simultaneously.
High Availability (HA) refers to the metric that defines how closely systems approach the goal of providing data availability 100% of the time while maintaining a high level of system performance.
Replication automatically copies data between two processing systems simultaneously on both systems (synchronous) or from a primary to a secondary location (asynchronous). CSPs offer several tiers of replication representing different high-availability service levels:
* Local replication—replicates your data within a single data center in the region where you created your storage account.
* Regional replication (zone-redundant storage)—replicates your data across multiple data centers within one or two regions.
* Geo-redundant storage (GRS)—replicates your data to a secondary region distant from the primary region.

#### Application Virtualization and Container Virtualization
Application virtualization is a software delivery model where the code runs on a server and is streamed to a client.
Containerization is an operating system virtualization deployment containing everything required to run a service, application, or microservice.

#### Cloud Architecture
Serverless computing refers to the features and capabilities of a server without needing to perform server administration tasks. It offloads infrastructure management to the cloud service provider.
Virtual Private Cloud (VPC) is a private network segment made available to a single cloud consumer on a public cloud.
A microservice is an independent, single-function module with well-defined lightweight interfaces and operations. It allows for rapid, frequent, and reliable delivery of complex applications.

#### Cloud Automation Technologies
Infrastructure as Code (IaC) refers to the provisioning architecture in which the deployment of resources is performed by scripted automation and orchestration.
Load balancing, edge computing, and auto-scaling are critical mechanisms to ensure responsiveness, improve performance, and effectively handle fluctuating workloads.

#### Software Defined Networking
Software-Defined Networking (SDN) refers to APIs and compatible hardware/virtual appliances allowing for programmable network appliances and systems.
Network functions can be divided into three "planes":
* Management plane—monitors traffic conditions and network status.
* Control plane—makes decisions about how traffic should be prioritized, secured, and where it should be switched.
* Data plane—handles the switching and routing of traffic and imposition of security access controls.

#### Cloud Architecture Features
Considerations for a cloud architecture are cost, scalability, resilience, ease of deployment, ease of recovery, Service Level Agreement (SLA), Interconnection Security Agreement (ISA), power, data protection, patching, and compute.

#### Cloud Security Considerations
A Software-Defined Wide Area Network (SD-WAN) is a service that uses software-defined mechanisms and routing policies to implement virtual tunnels and overlay networks over multiple types of transport networks.
Secure Access Service Edge (SASE) refers to networking and security architecture that provides secure access to cloud applications and services while reducing complexity. It combines security services like firewalls, identity and access management, and a secure web gateway with networking services.

### 6B: Embedded Systems and Zero Trust Architecture
#### Embedded Systems
An embedded system is an electronic system designed to perform a specific, dedicated function, such as a microcontroller in a medical drip or components in a control system managing a water treatment plant.
A Real-Time Operating System (RTOS) is an OS that prioritizes deterministic execution of operations to ensure consistent response for time-critical tasks.

#### Industrial Control Systems
Industrial Control System (ICS) is a network managing embedded device (computer systems designed to perform a specific, dedicated function).
Operation Technology (OT) is a communications network designed to implement an industrial control system rather than data networking.

#### Internet of Things
Internet of Things (IoT) refers to devices reporting state and configuration data and may be remotely managed over IP networks.

#### Deperimeterization and Zero Trust
Zero Trust refers to the security design paradigm where any request (host-to-host or container-to-container) must be authenticated before being allowed. The essential components of a Zero Trust architecture:
* Network and endpoint security
* Identity and access management (IAM)
* Policy-based enforcement
* Cloud security
* Network visibility
* Network segmentation
* Data protection
* Threat detection and prevention
Deperimeterization refers to a security approach that shifts the focus from defending a network's boundaries to protecting individual resources and data within the network.

#### Zero Trust Security Concepts
In zero trust architecture, the control plane has functions that define policy and determine access decisions. The policy decision point is comprised of the policy engine and policy administrator.
The zero trust model's fundamental concepts are to have adaptive identify recognition, threat scope reduction, and policy-driven access control.

---

# 7. Resiliency and Site Security Concepts

### 7A: Asset Management
#### Asset Tracking
An asset management process tracks all the organization's critical systems, components, devices, and valuable objects in an inventory, collecting and analyzing information about these assets so that personnel can make informed changes or work with assets to achieve business goals.
In asset management, assignment/accounting refers to processes that ensure each physical and data asset has an identified owner, and are appropriately tagged and classified within an inventory.
Monitoring/asset tracking refers to the enumeration and inventory processes and software that ensure physical and data assets comply with configuration and performance baselines, and have not been tampered with or suffered other unauthorized access. The ways to perform this, depending on the size and complexity of the organization and the types of assets involved:
* Manual Inventory
* Network Scanning
* Asset Management Software
* Configuration Management Database (CMDB)
* Mobile Device Management (MDM) Solutions
* Cloud Asset Discovery
Acquisition/procurement are policies and processes that ensure asset and service purchases and contracts are fully managed, and secure, use authorized suppliers/vendors, and meet business goals.

#### Asset Protection Concepts
A standard naming convention refers to applying consistent names and labels to assets and digital resources/identities within a configuration management system.
Configuration Management is a process through which an organization's information systems components are kept in a controlled state that meets the organization's requirements, including those for security and compliance.
Change control is the process of recording and approving the need for change.
Change management is the process through which changes to the configuration of information systems are implemented as part of the organization's overall configuration management efforts.

#### Data Backups
A backup refers to a security copy of production data made to removable media, typically according to a regular schedule. Different backup types (full, incremental, or differential) balance media capacity, time required to backup, and time to restore.
An on-site backup is a backup that writes job data to media stored in the same physical location as the production system.
An off-site backup is a backup that writes job data to media stored in a separate physical location to the production system.
Recovery is the operation to recover system functionality and or data integrity using backup media.

#### Advanced-Data Protection
A snapshot creates the entire architectural instance/copy of an application, disk, or system. It is used in backup processes to restore the system or disk of a particular device at a specific time. A snapshot backup can also be referred to as an image backup. Virtual Machine (VM), filesystem, and Storage Area Network (SAN) snapshots are three different types, each targeting a particular level of the storage hierarchy. Encryption of backups is essential.

#### Secure Data Destruction
In asset management, disposal/decommissioning refers to the policies and procedures governing the removal of devices and software from production networks, and their subsequent disposal through sale, donation, or waste. The methods are:
* Sanitization refers to thoroughly and completely removing data from a storage medium so file remnants cannot be recovered.
* Destruction refers to an asset disposal technique that ensures data remnants are rendered physically inaccessible and irrevocable, through degaussing, shredding, or incineration.
* Certification refers to an asset disposal technique that relies on a third party to use sanitization or destruction methods for data remnant removal and provides documentary evidence that the process is complete and successful.

### 7B: Redundancy Strategies
#### Continuity of Operations
A Continuity of Operation (COOP) identifies how business processes should deal with minor and disaster-level disruption by ensuring processing redundancy supports the workflow.

#### Capacity planning Risks
Capacity planning is a practice that involves estimating the personnel, storage, computer hardware, software, and connection infrastructure resources required over some future time. Cross-training, remote work plans, and or alternative reporting structures reduce the risk associated with capacity planning.

#### High Availability
High Availability (HA) is crucial in IT infrastructure, ensuring systems remain operational, can cope with rapid growth in demand, and are accessible with minimal downtime.
Scalability is the capacity to increase resources to meet demand within similar cost ratios and the two types are:
* Scaling out is to add more resources in parallel with existing resources.
* Scaling up is to increase the power of existing resources.
Elasticity refers to the system's ability to handle these changes on demand in real-time.
Fault-tolerant protects against system failure by providing extra (redundant) capacity and generally identifying and eliminating single points of failure.
Redundancy refers to overprovisioning resources at the component, host, or site level so there is a failover to a working instance in the event of a problem.
- Site resiliency is described as hot, warm, or cold.
    A hot site is a fully configured alternate processing site that can be brought online instantly or quickly after a disaster.
    A warm site is an alternate processing location that is dormant or performs noncritical functions under normal conditions, but which can be rapidly converted to a key operations site if needed.
    A cold site is a predetermined alternate location where a network can be rebuilt after a disaster.
Geographic dispersion is a resiliency mechanism where processing and data storage resources are replicated between physically distant sites.

#### Clustering
Clustering is a load-balancing technique where a group of servers are configured as a unit and work together to provide network services.
A failover is a technique that ensures a redundant component, device, or application can quickly and efficiently take over the functionality of an asset that has failed.

#### Power Redundancy
A Power Distribution Unit (PDU) is an advanced strip socket that provides filtered output voltage. A managed unit supports remote administration.
An Uninterruptible Power Supply (UPS) is a battery-powered device that supplies AC power that an electronic device can use in a power failure.
A backup power generator is a standby power supply fueled by diesel or propane. When a power outage occurs, a UPS must provide transitionary power, as a backup generator cannot be cut in fast enough.

#### Diversity and Defense in Depth
Platform diversity refers to a cybersecurity resilience strategy that increases attack costs by provisioning multiple types of controls, technologies, vendors, and crypto implementations.
Defense in depth is a comprehensive cybersecurity strategy that emphasizes the implementation of multiple layers of protection to safeguard an organization's information and infrastructure.
Vendor diversity offers benefits not only in cybersecurity, business resilience, innovation, competition, risk management, compliance, and customization and flexibility.
A multi-cloud strategy enhances cybersecurity by diversifying the risk associated with a single point of failure, as vulnerabilities or breaches in one cloud provider's environment are less likely to compromise the entire infrastructure and can improve security posture by implementing unique security features and services offered by different cloud providers.

#### Deception Technologies
Deception and disruption technologies refer to cybersecurity resilience tools and techniques to increase the cost of attack planning for the threat actor.
A honeypot consists of a host (honeypot), network (honeynet), file (honey file), or credential/token (honeytoken) that is set up to lure attackers away from assets of actual value and or discover attack strategies and weaknesses in the security configuration.
Fake telemetry is a deception strategy that returns spoofed data in response to network probes.
A DNS sinkhole is a temporary DNS record that redirects malicious traffic to a controlled IP address.

#### Testing Resiliency
By conducting various tests, organizations can identify potential vulnerabilities, evaluate the efficiency of their recovery strategies, and improve their overall preparedness for real-life incidents. Here are some methods:
* Tabletop Exercises involve teams discussing and working through hypothetical scenarios to assess their response plans and decision-making processes.
* Failover Tests involve intentionally causing the failure of a primary system or component to evaluate the automatic transfer of operations to a secondary, redundant system.
* Simulations are controlled experiments replicating real-world scenarios, allowing organizations to assess their incident response processes and system resilience under realistic conditions.
* Parallel Processing Tests involve running primary and backup systems simultaneously to validate the functionality and performance of backup systems without disrupting normal operations.
Documentation includes test plans outlining the objectives, scope, and methods of tests and the roles and responsibilities of individuals involved.

### 7C: Physical Security
#### Site Layout, Fencing, and Lighting
A barricade is something that prevents access. The purpose of barricades is to channel people through defined entry and exit points.
Fencing is a security barrier to prevent unauthorized access to a site perimeter.
Lighting is a physical security mechanisms that ensure a site is sufficiently illuminated for employees and guests to feel safe and for camera-based surveillance systems to work well.
Bollards is a sturdy vertical post installed to control road traffic or to prevent ram-raiding and vehicle-ramming attacks.
Methods of disguising the nature and purpose of buildings or parts of buildings.

#### Gateways and Locks
A secure gateway will normally be self-closing  Lock types can be categorized as physical, electronic, or biometric.
A proximity reader is a scanner that reads data from an RFID or NFC tag when in range.
An Access Control Vestibule (ACV) is a secure entry system with two gateways, only one open at any time.
A cable lock refers to devices that can be physically secured against theft using cable ties and padlocks. Some systems also feature lockable faceplates, preventing access to the power switch and removable drives.
Access badges refer to an authentication mechanism that allows a user to present a smart card to operate an entry system.

#### Security Guards and Cameras
Surveillance is a second layer of security designed to improve the resilience of perimeter gateways. Surveillance may be focused on perimeter areas or within security zones.
Video surveillance is a physical security control that uses cameras and recording devices to monitor the activity in a certain area visually. Camera systems and robotics can use AI and machine learning to implement smart physical security and some examples are motion recognition, object detection, and drones/UAVs.

#### Alarm Systems
Alarms alert security personnel and building occupants of potential threats or breaches and are labeled as detective and deterrent controls, notifying of trouble and discouraging unauthorized access and criminal activity. The types of alarms are circuit, motion detection, noise detection, proximity, and coercion.
A sensor is a component in an alarm system that identifies unauthorized entry via infrared-, ultrasonic-, microwave-, or pressure-based detection of thermal changes or movement.

---

# 8. Vulnerability Management

### 8A: Device and OS Vulnerabilities
#### Zero-Day Vulnerabilities
Zero-day vulnerabilities refer to a vulnerability in software unpatched by the developer or an attack that exploits such a vulnerability.

#### Misconfiguration Vulnerabilities
Misconfiguration of systems, networks, or applications is a common cause of security vulnerabilities. These can lead to unauthorized access, data leaks, or even full-system compromises.

#### Cryptographic Vulnerabilities
Cryptographic vulnerabilities refer to weaknesses in cryptographic systems, protocols, or algorithms that can be exploited to compromise data. Common secure key storage practices include hardware security modules (HSMs) or key management systems (KMS), implementing proper access controls and authentication mechanisms, and regularly monitoring and auditing key usage.

#### Sideloading, Rooting, and Jailbreaking
- Rooting and jailbreaking are methods used to gain elevated privileges and access to system files on mobile devices so that users bypass certain restrictions imposed by the device manufacturer or operating system.
    Rooting is gaining superuser-level access over an Android-based mobile device.
    Jailbreaking removes the protective seal and any OS-specific restrictions to give users greater control over the device.
Sideloading refers to installing an app on a mobile device without using an app store.

### 8B: Application and Cloud Vulnerabilities
#### Application Vulnerabilities
An application race condition is a software vulnerability when the resulting outcome from execution processes is directly dependent on the order and timing of certain events, and those events fail to execute in the order and timing intended by the developer.
Time-Of-Check-to-Time-Of-Use (TOCTOU) refers to the potential vulnerability that occurs when there is a change between when an app checks a resource and when the app uses the resource.
A memory injection is a vulnerability a threat actor can exploit to run malicious code with the same privilege level as the vulnerable process.
A buffer overflow is an attack in which data goes past the boundary of the destination buffer and begins to corrupt adjacent memory. This can allow the attacker to crash the system or execute arbitrary code.
A type-safe programming language is a program that enforces strict type-checking during compilation and ensures variables and data are used correctly. It prevents memory-related vulnerabilities and injection attacks.
A malicious update is a software repository or supply chain vulnerability that a threat actor can exploit to add malicious code to a package.

#### Evaluation Scope
Evaluation target or scope refers to the product, system, or service being analyzed for potential security vulnerabilities.
| Scope Practice | Description |
| --- | --- |
| Security Testing | Conducts vulnerability assessments and penetration testing to identify potential weaknesses, vulnerabilities, or misconfigurations. |
| Documentation Review | Reviewing documentation, such as design specifications, architecture diagrams, security policies, and procedures, to ensure the system is implemented according to secure design principles and compliance requirements. |
| Source Code Analysis | Analyzes source code to identify potential security vulnerabilities or coding errors to uncover issues related to input validation, secure coding practices, and coding standards. |
| Configuration Assessment | Evaluating configuration settings to ensure they align with security best practices and industry standards, such as assessing access controls, encryption settings, authentication mechanisms, and other security-related configurations. |
| Cryptographic Analysis | Assesses cryptographic mechanisms, including encryption algorithms, key management, and secure key storage, to ensure the proper implementation and use of cryptographic schemes according to industry standards and guidelines. |
| Compliance Verification | Verifies compliance with standards specified by relevant regulations, frameworks, or security certifications. |
| Security Architecture Review | Evaluates security architecture and design to identify potential weaknesses or gaps in security controls, such as insufficient segregation of duties, lack of audit trails, or inadequate access controls. |
A penetration tester’s scope is the specific system, application, network, or environment they are authorized to evaluate for exploitability.
An attacker’s scope describes their intended target. The attacker aims to identify and exploit vulnerabilities within the target to achieve their objectives, which could range from unauthorized access and data theft to service disruption or even system takeover.

#### Web Application Attacks
Web application attacks specifically target applications accessible over the Internet, exploiting vulnerabilities in these applications to gain unauthorized access, steal sensitive data, disrupt services, or perform other malicious activities.
Cross-Site Scripting (XSS) refers to a malicious script hosted on the attacker's site or coded in a link injected onto a trusted site designed to compromise clients browsing the trusted site, circumventing the browser's security model of trusted zones.
A Document Object Model (DOM) attack is when attackers send malicious scripts to a web app's client-side implementation of JavaScript to execute their attack solely on the client.
An SQL injection attack is an attack that injects a database query into the input data directed at a server by accessing the client side of the application.

#### Cloud-based Application Attacks
Cloud-based application attacks target applications hosted on cloud platforms and exploit potential vulnerabilities within these applications or the cloud infrastructure they run on to carry out malicious activities.
A Cloud Access Security Broker (CASB) is an enterprise management software designed to mediate access to cloud services by users across all types of devices.

#### Supply Chain
Software supply chain vulnerabilities refer to the potential risks and weaknesses introduced into software products during their development, distribution, and maintenance lifecycle. The supply chain describes many stages, from initial coding to end-user deployment, and includes various service providers, hardware providers, and software providers.

### 8C: Vulnerability Identification Methods
#### Vulnerability Scanning
Vulnerability management is a cornerstone of modern cybersecurity practices aimed at identifying, classifying, remediating, and mitigating vulnerabilities within a system or network.
A vulnerability scanner refers to a hardware or software configured with a list of known weaknesses and exploits that can scan for their presence in a host OS or particular application. 
A non-credentialed scan is a scan that uses fewer permissions and many times can only find missing patches or updates.
A credentialed scan is a scan that uses credentials, such as usernames and passwords, to take a deep dive during the vulnerability scan, which will produce more information while auditing the network.
An application vulnerability scanning is a vulnerability testing tool designed to identify issues with application code and platform configuration, including web servers and web applications.
Static analysis is the process of reviewing uncompiled source code either manually or using automated tools.
Dynamic analysis refers to software testing that examines code behavior during runtime. It helps identify potential security issues, potential performance issues, and other problems.
Package monitoring refers to techniques and tools designed to mitigate risks from application vulnerabilities in third-party code, such as libraries and dependencies.
A Software Bill of Materials (SBOM) is a list of detailed information about the software components and dependencies used in an application or system.
Software Composition Analysis (SCA) refers to tools to identify third-party and open-source code during software development and deployment.

#### Threat Feeds
Threat Feeds are signatures and pattern-matching rules supplied to analysis platforms as an automated feed. The outputs from the primary research undertaken by threat data feed providers and academics can take three main forms: behavioral threat research, reputational threat intelligence, and threat data.
Cyber Threat Intelligence (CTI) is investigating, collecting, analyzing, and disseminating information about emerging threats and threat sources.
Artificial Intelligence (AI) is the science of creating machines to develop problem-solving and analysis strategies without significant human direction or intervention.
A closed/proprietary basis is software code or security research that remains in the developer’s ownership and may only be used under permitted license conditions.
Information-sharing organizations are collaborative groups exchanging data about emerging cybersecurity threats and vulnerabilities.
Information Sharing and Analysis Center (ISAC) is a not-for-profit group set up to share sector-specific threat intelligence and security best practices among its members.
Open-Source Intelligence (OSINT) is publicly available information plus the tools used to aggregate and search it.

#### Deep and Dark Web
Tactics, Techniques, and Procedures (TTPs) are analyses of historical cyberattacks and adversary actions.
The dark web contains resources on the Internet that are distributed between anonymized nodes and protected from general access by multiple layers of encryption and routing. It is only accessible over a dark net. It is generally associated with illicit activities and illegal content but has legitimate purposes like privacy and anonymity, access to censored information, and research and information sharing.
The dark net is a network established as an overlay to Internet infrastructure by software, such as The Onion Router (TOR), Freenet, or I2P, that acts to anonymize usage and prevent a third party from knowing about the existence of the network or analyzing any activity taking place over the network.

#### Other Vulnerability Assessment Methods
Penetration testing or pen testing is a test that uses active tools and security utilities to evaluate security by simulating an attack on a system. It will verify that a threat exists, then actively test and bypass security controls, and exploit vulnerabilities in the system. The three types are unknown environment testing (black box), known environment testing (white box), and partially known environment testing (gray box).
A bug bounty is a reward scheme operated by software and web services vendors for reporting vulnerabilities.
A system/process audit is an audit process with a wide scope, including a supply chain assessment, configuration, support, monitoring, and cybersecurity factors.
Payment Card Industry Data Security Standard (PCI DSS) is the information security standard for organizations that process credit or bank card payments.

### 8D: Vulnerability Analysis and Remediation
#### Common Vulnerabilities and Exposures
A vulnerability feed is a synchronizable list of data and scripts used to check for vulnerabilities and can be referred to as plug-ins or network vulnerability tests (NVTs).
Security Content Automation Protocol (SCAP) is a NIST framework that outlines various accepted practices for automating vulnerability scanning.
Common Vulnerabilities and Exposures (CVE) is a scheme for identifying vulnerabilities developed by MITRE and adopted by NIST.
Common Vulnerability Scoring System (CVSS) is a risk management approach to quantifying vulnerability data and then considering the degree of risk to different types of systems or information.

#### False Positives, False Negatives, and Log Review
In security scanning, a false positive is a case that is reported when it should not be.
In security scanning, a false negative is a case that is not reported when it should be.

#### Vulnerability Analysis
- Vulnerability analysis supports several key aspects of an organization's cybersecurity strategy, including prioritization, vulnerability classification, exposure factor, organizational impact, environmental variables, and risk tolerance contexts.
    In risk calculation, the exposure factor is the percentage of an asset's value that would be lost during a security incident or disaster scenario.
    In vulnerability assessment, environmental variables factors, or metrics due to local network or host configuration that increase or decrease the base likelihood and impact risk level.
    Risk tolerance is a strategic assessment of residual risk level that is tolerable for an organization.

#### Vulnerability Response and Remediation
Vulnerability response and remediation practices encompass various strategies and tactics, including patching, insurance, segmentation, compensating controls, exceptions, and exemptions, each playing a distinct role in managing and mitigating cybersecurity risks.
Validation for a vulnerability ensures that the remediation actions have been implemented correctly and function as intended. Methods to perform this are re-scanning, auditing, and verification.
A comprehensive vulnerability report highlights the existing vulnerabilities and ranks them based on their severity and potential impact on the organization's assets, enabling the management to prioritize remediation efforts effectively.

---

# 9. Network Security Capabilities

### 9A: Network Security Baselines
#### Benchmarks and Secure Configuration Guides
A secure baseline is a configuration guide, benchmark, and best practices for deploying and maintaining a network device or application server safely for its given role.
Hardening makes a host or app configuration secure by reducing its attack surface, running only necessary services, installing monitoring software to protect against malware and intrusions, and establishing a maintenance schedule to ensure the system is patched to be secure against software exploits.

#### Wireless Network Installation Considerations
An access point is a device that provides a connection between wireless devices and can connect to wired networks, implementing an infrastructure mode WLAN.
Service Set Identifier (SSID) is a character string that identifies a particular wireless LAN (WLAN).
A site survey refers to documentation about a location to build an ideal wireless infrastructure; it often contains optimum locations for wireless antenna and access point placement to provide the required coverage for clients and identify sources of interference.

#### Wireless Encryption
Wi-Fi Protected Access (WPA) is a standard for authenticating and encrypting access to Wi-Fi networks.
A Wired Equivalent Privacy (WEP) is a legacy mechanism for encrypting data sent over a wireless connection.
Temporal Key Integrity Protocol (TKIP) is used in the first version of WPA to improve the security of wireless encryption mechanisms, compared to the flawed WEP standard.
Wi-Fi Protected Setup (WPS) is a feature of WPA and WPA2 that allows enrollment in a wireless network based on an eight-digit PIN.
Weaknesses found in WPA2 led to its intended replacement by WPA3. The main features of WPA3 are:
* Simultaneous Authentication of Equals (SAE)—a personal authentication mechanism for Wi-Fi networks introduced with WPA3 to address vulnerabilities in the WPA-PSK method.
* Enhanced Open—encrypts traffic between devices and the access points
* Updated Cryptographic Protocols—AES Galois Counter Mode Protocol (GCMP) is a high-performance mode of operation for symmetric encryption. It provides a special characteristic called authenticated encryption with associated data, or AEAD.
* Wi-Fi Easy Connect

#### Wi-Fi Authentication Methods
In WPA2, Pre-Shared Key (PSK) is a wireless network authentication mode where a passphrase-based mechanism allows group authentication to a wireless network. The passphrase is used to derive an encryption key.
Enterprise Authentication is a wireless network authentication mode where the access point acts as a pass-through for credentials verified by an AAA server.
The Remote Authentication Dial-In User Service (RADIUS) standard is published as an Internet standard.

#### Network Access Control
Network Access Control (NAC) is a general term for the collected protocols, policies, and hardware that authenticate and authorize access to a network at the device level.

### 9B: Network Security Capability Enhancement
#### Access Control Lists
An Access Control List (ACL) is a list of permissions associated with a network device that controls traffic at a network interface level.
A screened subnet is a segment isolated from the rest of a private network by one or more firewalls that accept connections from the Internet over designated ports.

#### Intrusion Detection and Prevention Systems
Intrusion Detection Systems (IDS) are designed to detect potential threats and generate alerts. They are passive, inspecting network traffic, identifying potential threats based on predefined rules or unusual behavior, and sending alerts to administrators.
Intrusion Prevention Systems (IPS) are proactive security tools that detect potential threats and take action to prevent or mitigate them. It identifies a threat using methods similar to an IDS and can block traffic from the offending source, drop malicious packets, or reset connections to disrupt an attack.

#### IDS and IPS Detection Methods
Signature-based detection is a network monitoring system that uses a predefined set of rules provided by a software vendor or security personnel to identify unacceptable events.
Behavioral-based detection section is a network monitoring system that detects changes in normal operating data sequences and identifies abnormal sequences.
Network Behavior and Anomaly Detection (NBAD) is a security monitoring tool that monitors network packets for anomalous behavior based on known signatures.
Heuristics is a method that uses feature comparisons and likenesses rather than specific signature matching to identify whether the target of observation is malicious.
Trend analysis is the process of detecting patterns within a dataset over time, and using those patterns to make predictions about future events or to better understand past events.

#### Web Filtering
Web filtering is a software application or gateway that filters client requests for various types of Internet content.

---

# 10. Assess Endpoint Security Capabilities

### 10A: Endpoint Security
#### Endpoint Hardening
Configuation baselines settings for services and policy configuration for a network appliance or for a server operating in a particular application role.

#### Endpoint Protection
Segmentation reduces the potential impact of a cybersecurity incident by isolating systems and limiting the spread of an attack or malware infection.
Device isolation removes or severely restricts communications paths to a particular device or system.
Antivirus software inspects traffic to locate and block viruses.
Full Disk Encryption (FDE) encrypts of all data on a disk can be accomplished via a supported OS, thirdparty software, or at the controller level by the disk device itself.
A Self-Encrypting Drive (SED) is a disk drive where the controller can automatically encrypt data that is written to it.
In storage encryption, Key Encryption Key (KEK) is the private key that is used to encrypt the symmetric bulk media encryption key (MEK). This means that a user must authenticate to decrypt the MEK and access the media.
A patch is a small unit of supplemental code meant to address either a security problem or a functionality flaw in a software package or operating system.
A patch management system identifies, tests, and deploys OS and application updates. Patches are often classified as critical, security-critical, recommended, and optional.

#### Advanced Endpoint Protection
An Endpoint Detection and Response (EDR) refers to a software agent that collects system data and logs for analysis by a monitoring system to provide early detection of threats.
A Host-Based Intrustion Detection System (HIDS) is a type of IDS that monitors a computer system for unexpected behavior or drastic changes to the system's state.
A Host-Based Intrustion Prevention System (HIPS) is a endpoint protection that can detect and prevent malicious activity via signature and heuristic pattern matching.
File Integrity Monitoring (FIM) refers to a type of software that reviews system files to ensure that they have not been tampered with.
User and Entity Behavior Analytics (UEBA) refers to a system that can provide automated identification of suspicious activity by user accounts and computer hosts.

#### Endpoint Configuration

#### Hardening Specialized Devices

### 10B: Mobile Device Hardening
#### Mobile Harding Techniques
Bring Your Own Device (BYOD) refers to the security framework and tools to facilitate using personally owned devices to access corporate networks and data.
Corporate Owned, Business Only (COBO) refers to enterprise mobile device provisioning model where the device is the property of the organization and personal use is prohibited.
Corporate Owned, Personally Enabled (COPE) refers to enterprise mobile device provisioning model where the device remains the property of the organization, but certain personal use, such as private email, social networking, and web browsing, is permitted.
Choose Your Own Device (CYOD) refers to enterprise mobile device provisioning model where employees are offered a selection of corporate devices for work and, optionally, private use.
Mobile Device Management (MDM) is the process and supporting technologies for tracking, controlling, and securing the organization's mobile infrastructure.

#### Location Services
Geolocation is the use of network attributes to identify (or estimate) the physical position of a device:
* Global Positioning System (GPS) determines the device's latitude and longitude based on information received from satellites via a GPS sensor.
* Indoor Positioning System (IPS) is a technology that can derive a device's location when indoors by triangulating its proximity to radio sources such as Bluetooth beacons or Wi-Fi access points.
Geofencing is a security control that can enforce a virtual boundary based on real-world geography.
GPS tagging is the process of adding geographical identification metadata, such as the latitude and longitude where the device was located at the time, to media such as photographs, SMS messages, video, and so on.

#### Cellular
Cellular are standards for implementing data access over cellular networks are implemented as successive generations. For 2G (up to about 48 Kb/s) and 3G (up to about 42 Mb/s), there are competing GSM and CDMA provider networks. Standards for 4G (up to about 90 Mb/s) and 5G (up to about 300 Mb/s) are developed under converged LTE standards.

#### Wi-Fi and Tethering Connection Methods
Personal Area Network (PAN) is a network scope that uses close-range wireless technologies (usually based on Bluetooth or NFC) to establish communications between personal devices, such as smartphones, laptops, and printers/peripheral devices.
An ad hoc network is a  type of wireless network where connected devices communicate directly with each other instead of over an established medium.
Tethering is using the cellular data plan of a mobile device to provide Internet access to a laptop or PC. The PC can be tethered to the mobile by USB, Bluetooth, or Wi-Fi (a mobile hotspot).

#### Bluetooth Connection Methods
Bluetooth is a short-range, wireless radio-network-transmission medium normally used to connect two personal devices. Some security issues with this are device discovery, authentication and authorization, and malware. The security features are paring and authentication, bluetooth permissions, encryption, Bluetooth Secure Connections (BISC), and Bluetooth Low Energy Privacy (BLE).
Bluesnarfing refers to a wireless attack where an attacker gains access to unauthorized information on a device using a Bluetooth connection.

#### Near-Field Communications and Mobile Payment Services
Near-Field Communication (NFC) is a standard for two-way radio communications over very short (around four inches) distances, facilitating contactless payment and similar technologies. NFC is based on RFID.

---

# 11. Enhance Application Security Capailities

### 11A. Application Protocol Security Baselines
#### Transport Layer Security
Transport Layer Security (TLS) is a security protocol that uses certificates for authentication and encryption to protect web communications and other application protocols.
Cipher Suites is a lists of cryptographic algorithms that a server and client can use to negotiate a secure connection.

#### Secure Directory Services
Authentication (referred to as binding to the server) can be implemented in the following ways:
* No Authentication
* Simple Bind—means the client must supply its distinguished name (DN) and password, but these are passed as plaintext.
* Simple Authentication and Security Layer (SASL)—means the client and server negotiate the use of a supported authentication mechanism.
* LDAP Secure (LDAPS) is a method of implementing LDAP using SSL/TLS encryption—means the server is installed with a digital certificate, which it uses to set up a secure tunnel for the user credential exchange. LDAPS uses port 636.

#### Simple Network Management Protocol Security
Simple Network Management Protocol (SNMP) is an application protocol used for monitoring and managing network devices. SNMP works over UDP ports 161 and 162 by default.

#### File Transfer Services
File Transfer Protocol (FTP) is an application protocol used to transfer files between network hosts. Variants include S(ecure)FTP, FTP with SSL (FTPS and FTPES), and T(rivial)FTP. FTP utilizes ports 20 and 21. The two types are:
* Explicit TLS (FTPES)—uses the AUTH TLS command to upgrade an unsecure connection established over port 21 to a secure one.
* Implicit TLS (FTPS) is a type of FTP using TLS for confidentiality.—negotiates an SSL/TLS tunnel before the exchange of any FTP commands. This mode uses the secure port 990 for the control connection.
Secure File Transfer Protocol (SFTP) is a secure version of the File Transfer Protocol that uses a Secure Shell (SSH) tunnel as an encryption method to transfer, access, and manage files.

#### Email Services
Email services use two types of protocols:
* The Simple Mail Transfer Protocol (SMTP) which is an application protocol used to send mail between hosts on the Internet. Messages are sent between servers over TCP port 25 or submitted by a mail client over secure port TCP/587.
* A mailbox protocol
There are two ways for SMTP to use TLS:
* STARTTLS—is a command that upgrades an existing unsecure connection to use TLS.
* SMTPS—establishes the secure connection before any SMTP commands are exchanged.
Post Office Protocol v3 (POP3) is an application protocol that enables a client to download email messages from a server mailbox to a client over port TCP/110 or secure port TCP/995.
Internet Message Access Protocol (IMAP) is an application protocol providing a means for a client to access and manage email messages stored in a mailbox on a remote server. IMAP4 utilizes TCP port number 143, while the secure version IMAPS uses TCP/993.

#### Email Security
Sender Policy Framework (SPF) is a DNS record identifying hosts authorized to send mail for the domain.
Domain Keys Identified Mail (DKIM) is a cryptographic authentication mechanism for mail utilizing a public key published as a DNS record.
Domain-based Message Authentication Reporting & Conformance (DMARC) is a framework for ensuring proper application of SPF and DKIM, utilizing a policy published as a DNS record.

#### Email Data Loss Prevention
Data Loss Prevention (DLP) is a software solution that detects and prevents sensitive information from being stored on unauthorized systems or transmitted over unauthorized networks.

#### DNS Filtering
Domain Name System (DNS) filtering is a technique that blocks or allows access to specific websites by controlling the resolution of domain names into IP addresses.
DNS Security Extensions (DNSSEC) is a security protocol that provides authentication of DNS data and upholds DNS data integrity.

### 11B: Cloud and Web Application Security Concepts
#### Secure Coding Techniques
Input validation is any technique used to ensure that the data entered into a field or variable in an application is handled appropriately by that application.
Cookies is a text file used to store information about a user when they visit a website. Some sites use cookies to support user sessions.
Static code analysis is scrutinizing source code to identify potential vulnerabilities, errors, and noncompliant coding practices before the program is finalized.
Code Signing is the method of using a digital signature to ensure the source and integrity of programming code.

#### Application Protections
Data exposure is a software vulnerability where an attacker is able to circumvent access controls and retrieve confidential or sensitive data from the file system or database.
An exception is an aapplication vulnerability that is defined by how an application responds to unexpected errors that can lead to holes in the security of an app.
A Structured Exception Handler (SEH) is a mechanism to account for unexpected error conditions that might arise during code execution. Effective error handling reduces the chances that a program could be exploited.

#### Software Sandboxing
Sandboxing is a  computing environment that is isolated from a host system to guarantee that the environment runs in a controlled, secure fashion. Communication links between the sandbox and the host are usually completely prohibited so that malware or faulty software can be analyzed in isolation and without risk to the host.

---

# 12. Incident Response and Monitoring Concepts

### 12A: Incident Response
#### Incident Response Processes
An incident is an event that interrupts standard operations or compromises security policy.
Incident Response Lifecycle are procedures and guidelines covering appropriate priorities, actions, and responsibilities in the event of security incidents, divided into preparation, detection, analysis, containment, eradication/recovery, and lessons learned stages.

#### Preparation
Preparation is an incident response process that hardens systems, defines policies and procedures, establishes lines of communication, and puts resources in place.
Cybersecurity infrastructure is hardware and software tools that facilitate incident detection, digital forensics, and case management
Computer Incident Response Team (CIRT), Computer Security Incident Response Team (CSIRT), or Computer Emergency Response Team (CERT) may located within a Security Operations Center (SOC).
An incident response plan are specific procedures that must be performed if a certain type of event is detected or reported.

#### Detection
Detection is an incident response process that correlates event data to determine whether they are indicators of an incident.
First responder refers to the first experienced person or team to arrive at the scene of an incident.

#### Analysis
Analysis is an incident response process in which indicators are assessed to determine validity, impact, and category.
Factors that affect determines the impact of an incident are data integrity, downtime, economic/publicity, scope, detection time, and recovery time.
Incident categories and definitions ensure that all response team members and other organizational personnel have a shared understanding of the meaning of terms, concepts, and descriptions.
Kill chain is a model developed by Lockheed Martin that describes the stages by which a threat actor progresses to a network intrusion.
A playbook is a checklist of actions to perform to detect and respond to a specific type of incident.

#### Containment
Containment refers to the practices and technologies used to identify, isolate, and limit the impact of cyber threats within an organization's network or systems.
Isolation-based containment involves removing an affected component from whatever larger environment it is a part of.
Segmentation-based containment is a means of achieving the isolation of a host or group of hosts using network technologies and architecture.

#### Eradication and Recovery
Eradication is an incident response process in which malicious tools and configurations on hosts and networks are removed.
Recovery is an incident response process in which hosts, networks, and systems are brought back to a secure baseline configuration.
Eradication of malware or other intrusion mechanisms and recovery from the attack steps are reconstitution of affected system, reaudit security controls, then Ensure that affected parties are notified and provided with the means to remediate their own systems.

#### Lessons Learned
Lesson learned is the process of reviewing the severe security incidents to determine their root cause, whether they were avoidable, and how to avoid them in the future.
Lessons Learned Report (LLR) is an analysis of events that can provide insight into how to improve response and support processes in the future.
Root cause analysis is a technique used to determine the true cause of the problem that, when removed, prevents the problem from occurring again.

#### Testing and Training
Testing and training validate the preparation process and show that the organization as a whole is ready to perform incident response.
Testing on specific incident response scenarios can use three forms which are tabletop exercises, walkthroughs, and simulations.

#### Threat Hunting
Threat hunting is a cybersecurity technique designed to detect the presence of threats that have not been discovered by normal security monitoring.

### 12B: Digital Forensics
#### Due Process and Legal Hold
Digital forensics is the process of gathering and submitting computer evidence for trial. Digital evidence is latent, meaning that it must be interpreted. This means that great care must be taken to prove that the evidence has not been tampered with or falsified.
Due process is a term used in US and UK common law to require that people only be convicted of crimes following the fair application of the laws of the land.
Legal hold is a process designed to preserve all relevant information when litigation is reasonably expected to occur.

#### Acquisition
Acquisition is the process of obtaining a forensically clean copy of data from a device seized as evidence.
In digital forensics, data acquisition is the method and tools used to create a forensically sound copy of data from a source device, such as system memory or a hard disk.
Order of volatility is the order in which volatile data should be recovered from various storage locations and devices after a security incident occurs.
1. CPU registers and cache memory (including cache on disk controllers, graphics cards, and so on).
2. Contents of nonpersistent system memory (RAM), including routing table, ARP cache, process table, kernel statistics.
3. Data on persistent mass storage devices (HDDs, SSDs, and flash memory devices):
    * Partition and file system blocks, slack space, and free space.
    * System memory caches, such as swap space/virtual memory and hibernation files.
    * Temporary file caches, such as the browser cache.
    * User, application, and OS files and directories.
4. Remote logging and monitoring data.
5. Physical configuration and network topology.
6. Archival media and printed documents.

#### System Memory Acquisition
System memory is volatile data held in Random Access Memory (RAM) modules. Volatile means that the data is lost when power is removed.

A $\color{#a5d6ff}{system\ memory\ dump}$ is a file containing data captured from system memory.

#### Disk Image Acquisition
Disk image acquisition refers to acquiring data from nonvolatile storage.Nonvolatile storage includes hard disk drives (HDDs), solid state drives (SSDs), firmware, other types of flash memory (USB thumb drives and memory cards), and optical media (CD, DVD, and Blu-ray)
- There are three device states for persistent storage acquisition:
    - Live acquisition—this means copying the data while the host is still running.
    - Static acquisition by shutting down the host—this runs the risk that the malware will detect the shutdown process and perform anti-forensics to try to remove traces of itself.
    - Static acquisition by pulling the plug—this means disconnecting the power at the wall socket (not the hardware power-off button).

The $\color{#a5d6ff}{dd\ command\ }$ is a linux command that makes a bit-by-bit copy of an input file, typically used for disk imaging.

#### Preservation
In digital forensics, $\color{#a5d6ff}{timeline}$ is a tool that shows the sequence of file system events within a source image in a graphical format.

In digital forensics, $\color{#a5d6ff}{provenance\ }$ is being able to trace the source of evidence to a crime scene and show that it has not been tampered with.

A $\color{#a5d6ff}{write\ block\ }$ is a forensic tool to prevent the capture or analysis device or workstation from changing data on a target disk or media.

$\color{#a5d6ff}{Chain\ of\ custody\ }$ are records of handling evidence from collection to presentation in court to disposal.

#### Reporting
$\color{#a5d6ff}{Reporting}$ is a forensics process that summarizes significant contents of digital data using open, repeatable, and unbiased methods and tools.

$\color{#a5d6ff}{E-discovery}$ are procedures and tools to collect, preserve, and analyze digital evidence. Some of the functions of e-discovery suites are identify and de-duplicate files and metadata, search, tags, secuirty, and disclosure.

### 12C: Data Sources

#### Data Sources, Dashboards, and Reports
$\color{#a5d6ff}{Event\ Dashboard}$ is a console presenting selected information in an easily digestible format, such as a visualization.

A $\color{#a5d6ff}{visualization}$ is a widget showing records or metrics in a visual format, such as a graph or table.

#### Log Data
$\color{#a5d6ff}{Log\ Data}$ is OS and applications software that can be configured to log events automatically. This provides valuable troubleshooting information. Security logs provide an audit trail of actions performed on the system as well as warning of suspicious activity. It is important that log configuration and files be made tamperproof.

$\color{#a5d6ff}{Metadata}$ is information stored or recorded as a property of an object, state of a system, or transaction.

$\color{#a5d6ff}{Event\ viewer}$ is a Windows console related to viewing and exporting events in the Windows logging file format.

$\color{#a5d6ff}{Syslog}$ is an application protocol and event-logging format enabling different appliances and software applications to transmit logs or event records to a central server. Syslog works over UDP port 514 by default. A syslog message comprises a PRI primary code, a header, and a message part.

#### Host Operating System Logs
$\color{#a5d6ff}{Security\ logs}$ target for event data related to access control, such as user authentication and privilege use.

#### Application and Endpoint Logs
$\color{#a5d6ff}{Application\ logs}$ target for event data relating to a specific software app or package.

$\color{#a5d6ff}{Endpoint\ logs}$ target for security-related events generated by host-based malware and intrusion detection agents.

A vulnerability scanner can be configured to log each vulnerability detected to a SIEM. Vulnerabilities can include missing patches and noncompliance with a baseline security configuration.

#### Network Data Sources Packet Captures
$\color{#a5d6ff}{Network\ logs}$ target for system and access events generated by a network appliance, such as a switch, wireless access point, or router.

$\color{#a5d6ff}{Firewall\ Logs}$ target for event data related to access rules that have been configured for logging.

An IPS/IDS log is an event when a traffic pattern is matched to a rule.

#### Packet Captures
$\color{#a5d6ff}{Packet\ analysis}$ is an analysis of the headers and payload data of one or more frames in captured network traffic.

#### Metadata
$\color{#a5d6ff}{Metadata}$ is information stored or recorded as a property of an object, state of a system, or transaction.

$\color{#a5d6ff} {Internet\ header}$ is a record of the email servers involved in transferring an email message from a sender to a recipient.

### 12D Alerting and Monitoring Tools
#### Security Information and Event Management
$\color{#a5d6ff}{System\ Information\ and\ Event\ Management\ (SIEM)}$ is a solution that provides real-time or near-real-time analysis of security alerts generated by network hardware and applications.

Collection is the means by which the SIEM ingests security event data from various sources. There are three main types of security data collection:
* Agent-based—uses an agent service on each host.
* $\color{#a5d6ff} {Listener/collector}$ -is a network appliance that gathers or receives log and/or state data from other network systems so hosts can be configured to push log changes to the SIEM server. 
* Sensor—as well as log data, the SIEM might collect packet captures and traffic flow data from sniffers. A sniffer can record network data using either the mirror port functionality of a switch or using some type of tap on the network media.

$\color{#a5d6ff} {Log\ aggregation}$ parses information from multiple log and security event data sources so that it can be presented in a consistent and searchable format.

#### Alerting and Monitoring Activites
$\color{#a5d6ff} {Correlation}$ is a function of log analysis that links log and state data to identify a pattern that should be logged or alerted as an event.

#### Alert Tuning
$\color{#a5d6ff} {Alert\ tuning}$ is the process of adjusting detection and correlation rules to reduce incidence of false positives and low-priority alerts. Some of the techniques used to manage alert tuning:
* Refining detection rules and muting alert levels
* Redirecting sudden alert "floods" to a dedicated group
* Redirecting infrastructure-related alerts to a dedicated group
* Continuous monitoring of alert volume and analyst feedback
* Deploying $\color{#a5d6ff} {Machine\ Learning\ (ML)}$ analysis—a component of AI that enables a machine to develop strategies for solving a task given a labeled dataset where features have been manually identified but without further explicit instructions.

A false negative is where the system fails to generate an alert about malicious indicators that are present in the data source.

#### Monitoring Infrastructure
$\color{#a5d6ff} {Network\ monitor}$ is an auditing software that collects status and configuration information from network devices. Many products are based on the Simple Network Management Protocol (SNMP).

A flow collector is a means of recording metadata and statistics about network traffic rather than recording each frame. 

$\color{#a5d6ff} {Netflow}$ Cisco-developed means of reporting network flow information to a structured database. NetFlow allows better understanding of IP traffic flows as used by different network applications and hosts.

$\color{#a5d6ff} {IP\ Flow\ Information\ Export\ (IPFIX)}$ Standards-based version of the Netflow framework.

A flow label is defined by packets that share the same key characteristics and the seven bits of information are referred to as a 7-tuple: source address, destination address, protocol, source port, destination port, input interface, and IP type of service data.

#### Monitoring Systems and Applications
$\color{#a5d6ff} {}$ Software that tracks the health of a computer's subsystems using metrics reported by system hardware or sensors. This provides an alerting service for faults such as high temperature, chassis intrusion, and so on.

A vulnerability scanner will report the total number of unmitigated vulnerabilities for each host.

$\color{#a5d6ff} {Antivirus\ scan (A-V)}$ is software capable of detecting and removing virus infections and (in most cases) other types of malware, such as worms, Trojans, rootkits, adware, spyware, password crackers, network mappers, DoS tools, and so on.
Data loss prevention (DLP) mediates the copying of tagged data to restrict it to authorized media and services.

#### Benchmarks
One of the functions of a vulnerability scan is to assess the configuration of security controls and application settings and permissions compared to established benchmarks.
Security Content Automation Protocol (SCAP) allows compatible scanners to determine whether a computer meets a configuration baseline. Important components of SCAP:
* Open Vulnerability and Assessment Language (OVAL)—an XML schema for describing system security state and querying vulnerability reports and information.
* Extensible Configuration Checklist Description Format (XCCDF)—an XML schema for developing and auditing best practice configuration checklists and rules.

---

# 13. Indicators of Malicious Activity

### 13A: Malware Attack Indicators
#### Malware Classification
$\color{#a5d6ff} {Malware}$ is software that serves a malicious purpose, typically installed without the user's consent (or knowledge). Some types of malware:

* Viruses and worms represent spread without any authorization from the user by being concealed within the executable code of another process.

* $\color{#a5d6ff} {Trojan}$ refers to malware concealed within an installer package for software that appears to be legitimate.

* $\color{#a5d6ff} {Potentially\ Unwanted\ Programs\ (PUPs)/Potentially\ Unwanted\ Applications\ (PUAs)}$ are software installed alongside a package selected by the user or perhaps bundled with a new computer system. It may have been installed without active consent or with consent from a purposefully confusing license agreement. This type of software is sometimes described as grayware or bloatware.

#### Computer Viruses
A $\color{#a5d6ff} {virus}$ is malicious code inserted into an executable file image. The malicious code is executed when the file is run and can deliver a payload, such as attempting to infect other files.

* Non-resident/file infector—the virus is contained within a host executable file and runs with the host process.

* Memory resident—when the host file is executed, the virus creates a new process for itself in memory.

* Boot—the virus code is written to the disk boot sector or the partition table of a fixed disk or USB media and executes as a memory-resident process when the OS starts or the media is attached to the computer.

* Script and macro viruses—the malware uses the programming features available in local scripting engines for the OS and/or browser.

$\color{#a5d6ff} {Malicious\ process}$ is the process executed without proper authorization from the system owner for the purpose of damaging or compromising the system.

#### Computer Worms and Fileless Malware
A $\color{#a5d6ff} {worm}$ is a type of malware that replicates between processes in system memory and can spread over client/server network connections.

Fileless malware does not write its code to disk and uses lightweight shellcode to achieve a backdoor mechanism on the host. 
$\color{#a5d6ff} {Shellcode}$ is a lightweight block of malicious code that exploits a software vulnerability to gain initial access to a victim system. Fileless malware may use "live off the land" techniques rather than compiled executables to evade detection. This means that the malware code uses legitimate system scripting tools, notably PowerShell and Windows Management Instrumentation (WMI), to execute payload actions.

$\color{#a5d6ff} {Advance\ Persistent Treat\ (APT)}$ is an attacker's ability to obtain, maintain, and diversify access to network systems using exploits and malware.

#### Spyware and Keyloggers
Bloatware and malware can be used for different levels of monitoring:
* Tracking cookies—a cookie is a plaintext file, not malware, but if permitted by browser settings, third-party cookies can be used to record web activity, track the user's IP address, and harvest various other metadata.
* Supercookies and beacons-A supercookie is a means of storing tracking data in a non-regular way, such as saving it to cache without declaring the data to be a cookie or encoding data into header requests. A beacon is a single pixel image embedded into a website
* $\color{#a5d6ff} {Adware}$ -software that records information about a PC and its user. Adware is used to describe software that the user has acknowledged can record information about their habits.
* $\color{#a5d6ff} {Spyware}$ -software that records information about a PC and its users, often installed without the user's consent.
* $\color{#a5d6ff} {Keylogger}$ -malicious software or hardware that can record user keystrokes.

#### Backdoors and Remote Access Trojans
A $\color{#a5d6ff} {backdoor}$ is a mechanism for gaining access to a computer that bypasses or subverts the normal method of authentication.

A $\color{#a5d6ff} {Remote\ Access\ Trojan\ (RAT)}$ is malware that creates a backdoor remote administration channel to allow a threat actor to access and control the infected host.

$\color{#a5d6ff} {Command\ and\ Control\ (C2)}$ refers to the infrastructure of hosts and services with which attackers direct, distribute, and control malware over botnets.

$\color{#a5d6ff} {Convert\ channel}$ is a type of attack that subverts network security systems and policies to transfer data without authorization or detection.

$\color{#a5d6ff} {Internet\ Relay\ Chat\ (IRC)}$ is a group communications protocol that enables users to chat, send private messages, and share files.

#### Rootkits
$\color{#a5d6ff} {Rootkits}$ is a class of malware that modifies system files, often at the kernel level, to conceal its presence.

#### Ransomware, Crypto-Malware, and Logic Bombs
$\color{#a5d6ff} {Ransomware}$ is malware that tries to extort money from the victim by blocking normal operation of a computer and/or encrypting the victim’s files and demanding payment.

The crypto class of ransomware attempts to encrypt data files on any fixed, removable, and network drives. If the attack is successful, the user will be unable to access the files without obtaining the private encryption key, which is held by the attacker and it is extremely difficult to mitigate, unless the user has backups of the encrypted files.

$\color{#a5d6ff} {Crypto-mining}$ is malware that hijacks computer resources to create cryptocurrency.

A $\color{#a5d6ff} {logic\ bomb}$ is a malicious program or script that is set to run under particular circumstances or in response to a defined event.

#### TTPs and IoCs
* Tactic—high level description of a threat behavior.
* Technique—intermediate-level description of how a threat actor progresses a tactic.
* Procedure—detailed description of how a technique is performed.

$\color{#a5d6ff} {Indicator\ of\ Compromise\ (IoC)}$ is a sign that an asset or network has been attacked or is currently under attack.

#### Maalicious Activity Indicators
A sandbox is a system configured to be completely isolated from the production network so that the malware cannot "break out".

$\color{#a5d6ff} {Resource\ consumption}$ shows potential indicator of malicious activity where CPU, memory, storage, and/or network usage deviates from expected norms.

$\color{#a5d6ff} {Blocked\ content}$ is a potential indicator of malicious activity where audit logs show unauthorized attempts to read or copy a file or other data.

$\color{#a5d6ff} {Resource\ inaccessibility}$ is a potential indicator of malicious activity where a file or service resource that should be available is inaccessible.

Indicators of suspicious account behavior:

* $\color{#a5d6ff} {Account\ lockout}$ -policy that prevents access to an account under certain conditions.

* $\color{#a5d6ff} {Concurrent\ session\ usage}$ -a potential indicator of malicious activity where an account has started multiple sessions on one or more hosts.

* $\color{#a5d6ff} {Impossible\ travel}$ -a potential indicator of malicious activity where authentication attempts are made from different geographical locations within a short timeframe.

A threat actor will often try to cover their tracks by removing indicators from log files:

* $\color{#a5d6ff} {Missing\ logs}$ -a potential indicator of malicious activity where events or log files are deleted or tampered with.

* $\color{#a5d6ff} {Out-of-cycle\ logging}$ -a potential indicator of malicious activity where event dates or timestamps are not consistent.

### 13B: Physical and Network Attack Indicators
#### Physical Attacks
A $\color{#a5d6ff} {physical\ attack}$ is an attack directed against cabling infrastructure, hardware devices, or the environment of the site facilities hosting a network.

An $\color{#a5d6ff} {environmental\ attack}$ physical threat directed against power, cooling, or fire suppression systems.

$\color{#a5d6ff} {Radio\ Frequency\ ID}$ is a means of encoding information into passive tags, which can be energized and read by radio waves from a reader device.

* $\color{#a5d6ff} {Card\ cloning}$ refers to making a copy of a contactless access card.

* $\color{#a5d6ff} {Skimming}$ refers to making a duplicate of a contactless access card by copying its access token and programming a new card with the same data.

#### Network Attacks
A $\color{#a5d6ff} {network\ attack}$ is an attack directed against cabled and/or wireless network infrastructure, including reconnaissance, denial of service, credential harvesting, on-path, privilege escalation, and data exfiltration. Cyberattack lifecycle:

* $\color{#a5d6ff} {Reconnaissance}$ is the actions taken to gather information about an individual or organization's computer systems and software. This typically involves collecting information such as the types of systems and software used, user account information, data types, and network configuration.

* $\color{#a5d6ff} {Credential\ harvesting}$ refers to social engineering techniques for gathering valid credentials to use to gain unauthorized access.

* Denial of service (DoS) in a network context refers to attacks that cause hosts and services to become unavailable.

* Weaponization, delivery, and breach refer to techniques that allow a threat actor to get access without having to authenticate.

* Command and control (C2 or C&C), beaconing, and persistence refer to techniques and malicious code that allow a threat actor to operate a compromised host remotely, and maintain access to it over a period of time.

* Lateral movement, pivoting, and privilege escalation refer to techniques that allow the threat actor to move from host to host within a network or from one network segment to another, and to obtain wider and higher permissions for systems and services across the network.  $\color{#a5d6ff} {Lateral\ movement}$ is the process by which an attacker is able to move from one part of a computing environment to another. $\color{#a5d6ff} {Pivoting}$ is when an attacker uses a compromised host (the pivot) as a platform from which to spread an attack to other points in the network.

* Data exfiltration refers to obtaining an information asset and copying it to the attacker's remote machine.

#### Distributed Denial of SErvice Attacks
$\color{#a5d6ff} {Denial\ of\ Service\ (DoS)}$ is any type of physical, application, or network attack that affects the availability of a managed resource.

$\color{#a5d6ff} {Distributed\ Dos\ (DDos)}$ is an attack that involves the use of infected Internet-connected computers and devices to disrupt the normal flow of traffic of a server or service by overwhelming the target with traffic.

$\color{#a5d6ff} {SYN\ flood\ attack}$ is a DoS attack where the attacker sends numerous SYN requests to a target server, hoping to consume enough resources to prevent the transfer of legitimate traffic.

$\color{#a5d6ff} {Distributed\ Reflected\ DoS\ (DRDos)}$ is a malicious request to a legitimate server is created and sent as a link to the victim, so that a server-side flaw causes the malicious component to run on the target’s browser.

$\color{#a5d6ff} {Amplification\ attack}$ is a network-based attack where the attacker dramatically increases the bandwidth sent to a victim during a DDoS attack by implementing an amplification factor.

DDoS attacks can be diagnosed by traffic spikes that have no legitimate explanation, but they can usually only be mitigated by providing high availability services, such as load balancing and cluster services.

#### On-Path Attacks
An $\color{#a5d6ff} {on-path\ attack}$ is an attack where the threat actor makes an independent connection between two victims and is able to read and possibly modify traffic.

$\color{#a5d6ff} {Address\ Resolution\ Protocol\ (ARP)}$ is a broadcast mechanism by which the hardware MAC address of an interface is matched to an IP address on a local network segment.

$\color{#a5d6ff} {ARP\ poisoning}$ is a network-based attack where an attacker with access to the target local network segment redirects an IP address to the MAC address of a computer that is not the intended recipient. This can be used to perform a variety of attacks, including DoS, spoofing, and on-path (previously known as man-in-the-middle).

#### Domain Name Systems Attacks
The domain name system (DNS) resolves requests for named host and services to IP addresses.

$\color{#a5d6ff} {DNS\ poisoning}$ is an attack where a threat actor injects false resource records into a client or server cache to redirect a domain name to an IP address of the attacker's choosing.

#### Wireless Attacks
A rogue access point is one that has been installed on the network without authorization, whether with malicious intent or not.

An $\color{#a5d6ff} {evil\ twin}$ is a wireless access point that deceives users into believing that it is a legitimate network access point.

$\color{#a5d6ff} {Disassociation Attack}$ refers to spoofing frames to disconnect a wireless station to try to obtain authentication data to crack.

#### Password Attacks

$\color{#a5d6ff} {Password\ attack}$ refers to any attack where the attacker tries to gain unauthorized access to and use of passwords.

An online password attack is where the threat actor interacts with the authentication service directly.

An offline attack means that the attacker has managed to obtain a database of password hashes.

A $\color{#a5d6ff} {brute\ force\ attack}$ is a type of password attack where an attacker uses an application to exhaustively try every possible alphanumeric combination to crack encrypted passwords.

A $\color{#a5d6ff} {dictionary\ attack}$ is a type of password attack that compares encrypted passwords against a predetermined list of possible password values.

A $\color{#a5d6ff} {hybrid\ password\ attack}$ is an attack that uses multiple attack methods, including dictionary, rainbow table, and brute force attacks when trying to crack a password.

$\color{#a5d6ff} {Passowrd\ Spraying}$ refers to a brute force attack in which multiple user accounts are tested with a dictionary of common passwords.

#### Cryptographic Attacks
$\color{#a5d6ff} {Credential\ replay}$ refers to an attack that uses a captured authentication token to start an unauthorized session without having to discover the plaintext password for an account.

#### Malicious Code Indicators
$\color{#a5d6ff} {Downgrade\ attack}$ refers to a cryptographic attack where the attacker exploits the need for backward compatibility to force a computer system to abandon the use of encrypted messages in favor of plaintext messages.

In cryptography, $\color{#a5d6ff} {collision}$ is the act of two different plaintext inputs producing the same exact ciphertext output.

$\color{#a5d6ff} {Birthday\ attack}$ refers to a type of password attack that exploits weaknesses in the mathematical algorithms used to encrypt passwords, in order to take advantage of the probability of different password inputs producing the same encrypted output.

### 13C: Application Attack Indicators
#### Application Attacks
$\color{#a5d6ff} {Application\ attack}$ refers to an attack directed against a coding, implementation, or platform vulnerability in OS or application software. There are broadly two main scenarios for application attacks:

* Compromising the operating system or third-party apps on a network host by exploiting Trojans, malicious attachments, or browser vulnerabilities.

* Compromising the security of a website or web application.

$\color{#a5d6ff} {Arbitrary\ code\ execution}$ refers to a vulnerability that allows an attacker to run their own code or a module that exploits such a vulnerability.

$\color{#a5d6ff} {Remote\ code\ execution}$ refers to a vulnerability that allows an attacker to transmit code from a remote host for execution on a target host or a module that exploits such a vulnerability.

$\color{#a5d6ff} {Privilege\ escalation}$ is the practice of exploiting flaws in an operating system or other application to gain a greater level of access than was intended for the user or application. The two main types:

* $\color{#a5d6ff} {Vertical\ privilege\ escalation}$ refers to when an attacker can perform functions that are normally assigned to users in higher roles, and often explicitly denied to the attacker.

* $\color{#a5d6ff} {Horizontal\ privilege\ escalation}$ refers to when a user accesses or modifies specific resources that they are not entitled to.

A buffer is an area of memory that an application reserves to store some value. To exploit a buffer overflow vulnerability, the attacker passes data that deliberately fills the buffer to its end and then overwrites data at its start.

#### Replay Attacks
$\color{#a5d6ff} {Replay\ attack}$ refers to an attack where the attacker intercepts some authentication data and reuses it to try to reestablish a session.

#### Forgery Attacks
$\color{#a5d6ff} {Forgery attack}$ refers to an attack that exploits weak authentication to perform a request via a hijacked session.

$\color{#a5d6ff} {Cross-Site\ Request\ Forgery\ (CSRF)}$ is a malicious script hosted on the attacker's site that can exploit a session started on another site in the same browser.
br>$\color{#a5d6ff} {Server-Side\ Request\ Forgery\ (CSRF)}$ is an attack where an attacker takes advantage of the trust established between the server and the resources it can access, including itself.

#### Injection Attacks
In a web application, $\color{#a5d6ff} {server-side}$ refers to the input data that is executed or validated as part of a script or process running on the server. A server-side attack causes the server to do some processing or run a script or query in a way that is not authorized by the application design.

$\color{#a5d6ff} {Injection\ attack}$ refers to an attack that exploits weak request handling or input validation to run arbitrary code in a client browser or on a server.

$\color{#a5d6ff} {Extensible\ Markup\ Language\ (XML)}$ is a system for structuring documents so that they are human and machine readable. Information within the document is placed within tags, which describe how information within the document is structured. XML is used by apps for authentication and authorizations, and for other types of data exchange and uploading.

The Lightweight Directory Access Protocol (LDAP) is a query language and specifically used to read and write network directory databases. 

#### Directory Traversal and Command Injection Attacks
$\color{#a5d6ff} {Directory\ traversal}$ is an application attack that allows access to commands, files, and directories that may or may not be connected to the web document root directory.

$\color{#a5d6ff} {Canonicalization\ attack}$ is an attack method where input characters are encoded in such a way as to evade vulnerable input validation measures. Canonicalization refers to the way the server converts between the different methods by which a resource may be represented and submitted to the simplest (or canonical) method used by the server to process the input.

$\color{#a5d6ff} {Command\ injection}$ is where a threat actor is able to execute arbitrary shell commands on a host via a vulnerable web application.

#### URL Analysis
$\color{#a5d6ff} {Uniform\ Resource\ Locator\ (URL)}$ is an application-level addressing scheme for TCP/IP, allowing for human-readable resource addressing. For example: protocol://server/file, where "protocol" is the type of resource (HTTP, FTP), "server" is the name of the computer (www.microsoft.com), and "file" is the name of the resource you wish to access.

$\color{#a5d6ff} {Percent\ encoding}$ is a mechanism for encoding characters as hexadecimal values delimited by the percent sign.

#### Web Server Logs
Web servers are typically configured to log HTTP traffic that encounters an error or traffic that matches some predefined rule set.

---

# 14.Security Governance Concepts

### 14A: Policies, Standards, and Procedures
#### Policies
$\color{#a5d6ff} {Policy}$ refer to a strictly enforceable ruleset that determines how a task should be completed. Common Organizational Policies:

* $\color{#a5d6ff} {Acceptable\ Use\ Policy\ (AUP)}$-policy that governs employees' use of company equipment and Internet services. ISPs may also apply AUPs to their customers.

* $\color{#a5d6ff} {Information\ Security\ Policies}$-a document or series of documents that are backed by senior management and that detail requirements for protecting technology and information assets from threats and misuse.

* Business Continuity & Continuity of Operations Plans (COOP)-$\color{#a5d6ff} {business\ continuity}$ refers to a collection of processes that enable an organization to maintain normal business operations in the face of some adverse event.

* $\color{#a5d6ff} {Diaster\ Recovery}$-a documented and resourced plan showing actions and responsibilities to be used in response to critical incidents.

* Incident Response-outlines the processes to be followed after a security breach, or cyberattack occurs.

* $\color{#a5d6ff} {Software\ Developmnet\ Life\ Cycle\ (SDCL)}$-the processes of planning, analysis, design, implementation, and maintenance that often govern software and systems development.

* Change Management—Change management policies outline how changes to IT systems and software are requested, reviewed, approved, and implemented, including all documentation requirements.

$\color{#a5d6ff} {Guideline}$ refers to best practice recommendations and advice for configuration items where detailed, strictly enforceable policies and standards are impractical.

#### Procedures
$\color{#a5d6ff} {Procedure}$ refer to detailed instructions for completing a task in a way that complies with policies and standards.

Personnel management policies are applied in three phases which are recruitment (hiring), operation (working), and termination or separation (firing or retiring).

A background check determines that a person is who they say they are and are not concealing criminal activity, bankruptcy, or connections that would make them unsuitable or risky.

$\color{#a5d6ff} {Onboarding}$ is the process of bringing in a new employee, contractor, or supplier. Some processes invovled with this are secure transmission of credentials, asset allocation, and training/policies.

Playbooks guide personnel to ensure consistency in operations and improve quality and effectiveness.

The implementation of changes should be carefully planned, with consideration for how the change will affect dependent components.

Offboarding ensures that an employee leaves a company gracefully, including an exit interview for feedback. In terms of security, some process to be completed with this are account management, company assets, and personal assets.

#### Standards
$\color{#a5d6ff} {Standards}$ are expected outcome or state of a task that has been performed in accordance with policies and procedures. Standards can be determined internally, or measured against external frameworks.

Common industry standards used by public and private organizations include the following:
* ISO/IEC 27001 —An international standard that provides an information security management system (ISMS) framework to ensure adequate and proportionate security controls are in place.
* ISO/IEC 27002 —This is a companion standard to ISO 27001 and provides detailed guidance on specific controls to include in an ISMS.
* ISO/IEC 27017 —An extension to ISO 27001 and specific to cloud services.
* ISO/IEC 27018 —Another addition to ISO 27001, and specific to protecting personally identifiable information (PII) in public clouds.
* NIST (National Institute of Standards and Technology) Special Publication 800-63 —A US government standard for digital identity guidelines, including password and access control requirements.
* PCI DSS (Payment Card Industry Data Security Standard) —A standard for organizations that handle credit cards from major card providers, including requirements for protecting cardholder data.
* FIPS (Federal Information Processing Standards) —FIPS are standards and guidelines developed by NIST for federal computer systems in the United States that specify requirements for cryptography.

Password standards describe the specific technical requirements required to design and implement systems, including how passwords are managed within those systems to ensure that different systems can interoperate and use consistent password-handling methods.
* Hashing Algorithms —Defines requirements for the hash functions used to store passwords.
* Password Salting —Defines the methods used to protect password hashes to protect them from rainbow table attacks.
* Secure Password Transmission —Defines the methods for secure password transmission, including details regarding appropriate cipher suites.
* Password Reset —Defines appropriate identity verification methods to protect password reset requests from exploitation.
* Password Managers —Defines the requirements for password managers that organizations may choose to incorporate.

Access control standards ensure that only authorized individuals can access the systems and data they need to do their jobs to protect sensitive information and help prevent accidental changes or damage. Internally developed access control standards typically include the following elements:
* Access Control Models —Defines appropriate access models for different use cases. Examples include role-based access control (RBAC), discretionary access control (DAC), and mandatory access control (MAC), among others.
* User Identity Verification —Defines acceptable methods to verify identities before granting access.
* Privilege Management —Defines the methods for managing user privileges to ensure they have the minimum required access.
* Authentication Protocols —Defines specific acceptable authentication protocols, such as Kerberos, OAuth, or SAML.
* Session Management —Defines allowable session management practices, including requirements for session timeouts, secure generation and transmission of session cookies, and other similar requirements.
* Audit Trails —Defines mandatory audit capabilities designed to assist with identifying and investigating security incidents.

Physical security standards protect data centers, computer rooms, wiring closets, cabling, hardware, and infrastructure comprising the IT environment and the people who use and maintain them. Some examples include the following:
* Building Security —Methods for securing facilities, including card access systems, CCTV surveillance, and security personnel.
* Workstation Security —Standards for physically securing laptops or other portable devices.
* Datacenter and Server Room Security —Defines requirements for card access, biometric scans, sign-in/sign-out logs, and escorted access for visitors.
* Equipment Disposal —Defines requirements for securely disposing (or repurposing) equipment to ensure that sensitive data is irrecoverable.
* Visitor Management —Defines the requirements for managing visitors, such as sign-in/sign-out procedures, visitor badges, and escorted access requirements.

Encryption protects data from unauthorized access, and it is vital for securing data both at rest (stored data) and in transit (data being transmitted). Encryption standards identify the acceptable cipher suites and expected procedures needed to provide assurance that data remains protected.
* Encryption Algorithms —Defines allowable encryption algorithms, such as AES (Advanced Encryption Standard) for symmetric or ECC for asymmetric encryption.
* Key Length —Defines the minimum allowable key lengths for different types of encryption.
* Key Management —Defines how keys are generated, distributed, stored, and changed.

#### Legal Environment
$\color{#a5d6ff} {Sarbanes-Oxley\ Act\ (SOX)}$ is a law enacted in 2002 that dictates requirements for the storage and retention of documents relating to an organization's financial and business operations.

$\color{#a5d6ff} {General\ Data] Protection\ Regulation\ (GDPR)}$ Provisions and requirements protecting the personal data of European Union (EU) citizens. Transfers of personal data outside the EU Single Market are restricted unless protected by like-for-like regulations, such as the US's Privacy Shield requirements.

Industry-specific cybersecurity laws and regulations govern how data should be handled and protected:
- Healthcare
    - Health Insurance Portability and Accountability Act (HIPAA) (United States)
    - The General Data Protection Regulation (GDPR) (European Union)
- Financial Services
    - Gramm-Leach-Bliley Act (GLBA) (United States)
    - Payment Card Industry Data Security Standard (PCI DSS ) (Contractual obligation)
- Telecommunications
    - Communications Assistance for Law Enforcement Act (CALEA ) (United States )
- Energy
    - North American Electric Reliability Corporation (NERC) (United States and Canada)
    - Education & Children
    - Family Educational Rights and Privacy Act (FERPA) (United States)
    - Children's Internet Protection Act (CIPA) (United States)
    - Children's Online Privacy Protection Act (COPPA) (United States )
- Government
    - Federal Information Security Modernization Act (FISMA) (United States )
    - Criminal Justice Information Services (CJIS ) Security Policy (United States )
    - The Government Security Classifications (GSC) (United Kingdom)

#### Governance and Accountability
$\color{#a5d6ff} {Governance}$ refers to creating and monitoring effective policies and procedures to manage assets, such as data, and ensure compliance with industry regulations and local, national, and global legislation.

$\color{#a5d6ff} {Governance\ boards}$ refer to senior executives and external stakeholders with responsibility for setting strategy and ensuring compliance.

$\color{#a5d6ff} {Governance\ committees}$ are leaders and subject matter experts with responsibility for defining policies, procedures, and standards within a particular domain or scope.

Security governance relies heavily on specially designed and interdependent roles called owner, controller, processor, and custodian:
$\color{#a5d6ff} {Owner}$—a senior (executive) role with ultimate responsibility for maintaining the confidentiality, integrity, and availability of an information asset.
$\color{#a5d6ff} {Controller}$—in privacy regulations, the entity that determines why and how personal data is collected, stored, and used.
$\color{#a5d6ff} {Processor}$—in privacy regulations, an entity trusted with a copy of personal data to perform storage and/or analysis on behalf of the data collector.
$\color{#a5d6ff} {Custodian}$—an individual who is responsible for managing the system on which data assets are stored, including being responsible for enforcing access control, encryption, and backup/recovery measures.

### 14B: Change Management
#### Change Management Programs
Change management refers to a systematic approach that manages all changes made to a product or system, ensuring that methods and procedures are used to handle these changes efficiently and effectively.

$\color{#a5d6ff} {Stakeholder}$ refers to a person who has a business interest in the outcome of a project or is actively involved in its work.

#### Allowed and Blocked Changes
Allow and block lists describe software restriction approaches designed to control computer software.

#### Restarts, Dependencies, and Downtime
Service and application restarts, as well as downtime, are critical considerations because they typically have a direct impact on business operations.

$\color{#a5d6ff} {Dependencies}$ resources and other services that must be available and running for a service to start.

#### Documentation and Version Control
$\color{#a5d6ff} {Version\ control}$ refers to the practice of ensuring that the assets that make up a project are closely managed when it comes time to make changes.

### 14C: Automation and Orchestration
#### Automation and SCritping
In terms of governance, automation can help enforce security policies more consistently and efficiently, and it can aid in monitoring and reporting to provide valuable insights for leadership teams and risk managers. In change management, automation can reduce the risk of human error, reduce implementation time, and provide clear audit trails.

#### Automation and Orchestration Implementation
$\color{#a5d6ff} {Workforce\ multiplier}$ is a tool or automation that increases employee productivity, enabling them to perform more tasks to the same standard per unit of time.

Operator fatigue refers to the mental exhaustion experienced by cybersecurity professionals due to their work's continuous, high-intensity nature.

$\color{#a5d6ff} {Reaction\ time}$ refers to the elapsed time between an incident occurring and a response being implemented.

Challenges when it comes to automation and orchestration:
* Complexity—a poorly planned or executed automation strategy can add complexity, making systems more difficult to manage and maintain.
* Cost—The initial cost of implementing automation and orchestration can be high, including costs associated with acquiring and developing appropriate tools, integrating them into existing systems, and training staff to use them effectively. Automation software maintenance and upgrades can also be costly.
* Single Point of Failure—If a critical automated system or process fails, it could impact multiple areas of the organization, causing widespread problems.
* Technical Debt—Organizations can accrue technical debt if automation and orchestration tools are implemented hastily, resulting in poorly documented code, "brittle" system integrations, or poor maintenance. Over time, this debt can lead to system instability, complexity, and increased costs, ironically similar to the problems associated mainly with legacy systems.
* Ongoing Support—Automation and orchestration systems require ongoing support to stay effective and secure, including updates and patches, reviewing and improving automated processes, and continuous education. Without adequate support, the benefits of automation and orchestration are quickly eroded.

---

# 15. Risk Management Processes

### 15A: Risk Management Processes and Concepts
#### Risk Identification and Assessment
Within overall risk assessment, $\color{#a5d6ff} {Risk\ identification}$ is the specific process of listing sources of risk due to threats and vulnerabilities.

$\color{#a5d6ff} {Risk\ assessment}$ is the process of identifying risks, analyzing them, developing a response strategy for them, and mitigating their future impact.

$\color{#a5d6ff} {Risk\ analysis}$ is the process for qualifying or quantifying the likelihood and impact of a factor.

$\color{#a5d6ff} {Quantitative\ risk\ analysis}$ is a numerical method that is used to assess the probability and impact of risk and measure the impact.

* $\color{#a5d6ff} {Single\ Loss\ Expectancy\ (SLE)}$ is the amount that would be lost in a single occurrence of a particular risk factor.

* $\color{#a5d6ff} {Annualized\ Loss\ Expectancy\ (ALE)}$ is the total cost of a risk to an organization on an annual basis. This is determined by multiplying the SLE by the annual rate of occurrence (ARO). In risk calculation, $\color{#a5d6ff} {Annualized\ Rate\ of\ Occurence\ (ARO)}$ is an expression of the probability of a risk as the number of times per year a particular loss is expected to occur.

$\color{#a5d6ff} {Qualitative\ risk\ analysis}$ is the process of determining the probability of occurrence and the impact of identified risks by using logical reasoning when numeric data is not readily available.

$\color{#a5d6ff} {Inherent\ risk}$ is risk that an event will pose if no controls are put in place to mitigate it.

#### Risk Management Strategies
$\color{#a5d6ff} {Risk\ mitigation/remediation}$ is the response of reducing risk to fit within an organization's willingness to accept risk.

In risk mitigation, $\color{#a5d6ff} {risk\ deterrence/reduction}$ is the response of deploying security controls to reduce the likelihood and/or impact of a threat scenario.

In risk mitigation, $\color{#a5d6ff} {avoidance}$ is the practice of ceasing activity that presents risk.

In risk mitigation, $\color{#a5d6ff} {transference/sharing}$ is the response of moving or sharing the responsibility of risk to another entity, such as by purchasing cybersecurity insurance.

$\color{#a5d6ff} {Risk\ acceptance/tolerance}$ is the response of determining that a risk is within the organization's appetite and no countermeasures other than ongoing monitoring is needed.

$\color{#a5d6ff} {Risk\ excemption}$ is a category of risk management that uses alternate mitigating controls to control an accepted risk factor.

$\color{#a5d6ff} {Risk\ exemption}$ a category of risk management that accepts an unmitigated risk factor.

$\color{#a5d6ff} {Residual\ risk}$ is risk that remains even after controls are put into place.

#### Risk Management Procedures
$\color{#a5d6ff} {Risk\ management}$ is the cyclical process of identifying, assessing, analyzing, and responding to risks. The five processes performed with this is identify mission essential functions, identify vulnerabilities, identify threats, analyze business impacts, and identify risk response.

Calculating risk is complex but the main variables are:

* In risk calculation, $\color{#a5d6ff} {likelihood}$ is the chance of a threat being realized, expressed as a percentage.

* $\color{#a5d6ff} {Probability}$ is the mathematical measure of the possibility of a risk occurring.

* $\color{#a5d6ff} {Impact}$ is the severity of the risk if realized by factors such as the scope, value of the asset, or the financial impacts of the event.

$\color{#a5d6ff} {Enterprise\ risk\ management\ (ERM)}$ is the comprehensive process of evaluating, measuring, and mitigating the many risks that pervade an organization.

$\color{#a5d6ff} {Risk\ register}$ refers to a document highlighting the results of risk assessments in an easily comprehensible format (such as a "traffic light" grid). Its purpose is for department managers and technicians to understand risks associated with the workflows that they manage.

$\color{#a5d6ff} {Heat\ map\ risk\ matrix}$ refers to a graphical table indicating the likelihood and impact of risk factors identified for a workflow, project, or department for reference by stakeholders.

Risk threshold defines the limits or levels of acceptable risk an organization is willing to tolerate.

$\color{#a5d6ff} {Key\ Risk\ Indicator\ (KRI)}$ is the method by which emerging risks are identified and analyzed so that changes can be adopted to proactively avoid issues from occurring.

$\color{#a5d6ff} {Risk\ owner}$ refers to an individual who is accountable for developing and implementing a risk response strategy for a risk documented in a risk register.

$\color{#a5d6ff} {Risk\ appetite}$ is a strategic assessment of what level of residual risk is tolerable for an organization. The three levels of this are expansionary, conservative, and neutral.

$\color{#a5d6ff} {Risk\ tolerance}$ determines the thresholds that separate different levels of risk.

$\color{#a5d6ff} {Risk\ reporting}$ is a periodic summary of relevant information about a project’s current risks. It provides a summarized overview of known risks, realized risks, and their impact on the organization.

#### Business Impact Analysis
$\color{#a5d6ff} {}$

### 15B: Vendor Management Concepts
#### Vendor Slection
$\color{#a5d6ff} {}$

#### Vendor Assessment Methods
$\color{#a5d6ff} {}$

#### Legal Agreements
$\color{#a5d6ff} {}$

### 15C: Audits and Assessments
#### Attestation and Assessments
$\color{#a5d6ff} {}$

#### Penetration Testing
$\color{#a5d6ff} {}$

### Exercise Types
$\color{#a5d6ff} {}$

---

# 16. Data Protection and Compliance Concepts

### 16A: Data Classification and Compliance
#### Data Types
$\color{#a5d6ff} {}$

#### Data Classifications

#### Data Sovereignty and Geographical Considerations

#### Privacy Data

#### Privacy Breaches and Data Breaches

#### Compliance

#### Monitoring and Reporting

#### Data Protection

#### Data Loss Prevention

### 16B: Personnel Policies
#### Conduct Policies

#### User and Role-Based Training

#### Training Topics and Techniques

#### Security Awareness Training Lifecycle
$\color{#a5d6ff} {}$