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

#### Denial of services(Dos)
- Consume resource of container to disrupt the ability of containerized applications

#### Create client certificate credential.
- Attacker can steal those credential to authenticate and access to the cluster with credential assigned privileges.

#### Create long-lived token.
- By someway, the attacker can gain such token and have an unexpected long period of time to access to the system.

