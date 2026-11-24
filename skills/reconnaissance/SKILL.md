# Reconnaissance & Attack Surface Mapping Skill

## When to Use
Use this skill at the initiation of an authorized security assessment to discover reachable network interfaces, open services, hostnames, and technology stacks.

## Objective
Identify active assets, exposed network ports, and running service banners within the authorized target scope without performing intrusive exploitation.

## Required Input
- `target`: Authorized domain name, hostname, or IP address.
- `scope_confirmation`: Verification that target is registered in Sensei Scope Registry.

## Available Tools
- `nmap`: Safe non-intrusive service discovery (`-sV --version-light -Pn`).
- `http_audit`: Host banner discovery and technology fingerprinting.

## Execution Methodology
1. Normalize and resolve the target hostname.
2. Verify explicit user authorization in the scope registry.
3. Perform passive or lightweight service enumeration on standard web and API ports (80, 443, 3000, 8000, 8080).
4. Record open ports, service versions, and server headers.
5. Feed discovered services into specialist downstream workflows.

## Validation Criteria
- Service banner or port state must be verified with active TCP response.
- Do not infer open ports without handshake verification.

## Safety Restrictions
- Strictly prohibited: SYN floods, UDP flooding, aggressive OS fingerprinting, full 65535 port sweeps without prior authorization.
- Enforce token-bucket rate limits (maximum 2-5 requests per second).

## Expected Output
- Structured list of open ports and services.
- Server banners and identified framework technologies.
