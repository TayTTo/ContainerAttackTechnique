# Attack methods to system using container.
#### Attacks abusing insecure container images.
- Attackers can abuse vulnerable or outdated software components to do malicious activities on the system.
#### Abusing privileged container.
- Attackers can gain control over the underlying host system through running container with root-level access.

#### Abusing environment misconfiguration.
- Attacker can abuse an application to access resources outside it's container if that container's access controls are misconfigured.

#### Supply chain vulnerabilities.
- Application often use third-party dependencies, container can create vulnerable or contain malicious code.

#### Container escape techniques.
1. Mount the host filesystem.
- Escape from container by mounting the host filesystem.
- Minimal required Linux capabilities: SYS_ADMIN.

2. Use a mounted docker socket.
- If the docker socket is mounted inside container, the container can gain administrative control over the Docker host.
- Minimal Linux required Linux capabilities: no.

3. Process injection.
- This is the technique that use a process to write into the memory of another process to execute a shellcode .
- Minimal required Linux capabilities: SYS_PTRACE.

4. Shared kernel exploitation.
- A container cal load and unload kernel modules into the shared kernel.
- Minimal required Linux capabilities: SYS_MODULE.

5. Dump host secrets.
- This technique refers to unauthorized extraction of sensitive information stored within cluster.

#### Container image tampering.
- Modifying or replacing container images with malicious versions that may contain malware, backdoors, or vulneralbe components.
#### Privilege escalation through node/proxy permissions

#### Denial of services(Dos)
- Consume resource of container to disrupt the ability of containerized applications

#### Create client certificate credential.
- Attacker can steal those credential to authenticate and access to the cluster with credential assigned privileges.

#### Create long-lived token.
- By someway, the attacker can gain such token and have an unexpected long period of time to access to the system.

#### Abusing kernel vulnerabilities.
- Attackers can abuse kernel vulnerabilities in the system's operating system to gain higher access right to the system. For example: Abuse kernel vulnerabilities to gain root access to the system.

#### Abusing volume hostPath mount.
- Attackers can escape pod's containerized environment and have higher access right to the systeme by creating a pod that mount the entire node's root filesystem using the hostPath volume.


## Some CVE related to container attacks.
1. CVE-2024-8695
- CVSS 3.1(Common Vulnerability Scoring System) score 9.8 of 10:
- Attack complexity: Low
- Confidentially: High
- Integrity: High
- Availability: High
- Scope: Unchanged
- Privileges required: None
- Published: Sep 13, 2024.
- CWE ID 94: Improper Control of Generation of Code ('Code Injection')
- CWE ID 79:Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') 

- Summary information:
    - Remote code execution vulnerability affecting Docker Desktop versions prior to 4.34.2.
    - Exploitable through malicious extensions.
    - High risk with potential impacts on confidentiality, integrity, and availability.
    - To avoid this breach, user should update to version 4.34.2

- Reference for this CVE:
    - https://www.recordedfuture.com/vulnerability-database/CVE-2024-8695
    - https://nvd.nist.gov/vuln/detail/CVE-2024-8695
    - https://securityonline.info/cve-2024-8695-cve-2024-8696-two-critical-rce-flaws-discovered-in-docker-desktop/?&web_view=true#google_vignette


2. CVE-2021-41091.
- CVSS 3.1: 6.3
- Attack complexity: Low 
- Confidentially: Low
- Integrity: Low
- Availability: Low
- Scope: changed
- Privileges required: Low
- Published: Sep 15, 2021. (Source: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41091)
- CWE-732: Incorrect Permission Assignment for Critical Resource.
- CWE-281: Improper Preservation of Permissions.

- Summary:
    - Related to Moby (an open-source project).
    - Data directory contains subdirectories with low restriction in permissions, allow unprivileged user to traverse directory.
    - The bug have been fixed in version 20.10.9 in Moby.


- References:
    - https://nvd.nist.gov/vuln/detail/cve-2021-41091
    - https://www.suse.com/security/cve/CVE-2021-41091.html
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41091


3. CVE-2024-6222
- CVSS 4.0: 7.3
- Attack complexity: High
- Confidentially: High
- Integrity: High
- Availability: High
- Scope: Unchanged
- Privileges required: Low
- Published: Jul 10, 2024
- CWE-923: Improper restriction of Communication Chanel to Intended Endpoints.

- Summary:
    - Relates to Docker Desktop before v4.29.0.
    - Attackers who can access to Docker Desktop VM through container breakout can further escape to the host.
    - At version 4.29.0, this problem is fixed and then in v4.31.0 enable "Allow only extensions distributed through the Docker Marketplace" by default to avoid this kind of exploitation.
- References:
    - https://www.cve.org/CVERecord?id=CVE-2024-6222
    - https://nvd.nist.gov/vuln/detail/CVE-2024-6222
    - https://feedly.com/cve/CVE-2024-6222
## Reference
1. https://www.practical-devsecops.com/container-security-risks/ 
2. https://devsecopsguides.com/docs/attacks/container/
3. https://www.panoptica.app/research/7-ways-to-escape-a-container

