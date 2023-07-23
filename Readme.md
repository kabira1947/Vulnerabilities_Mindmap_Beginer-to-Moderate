# Server-Side Request Forgery (SSRF) Vulnerability

## Definition
SSRF is a web vulnerability that allows attackers to make HTTP requests from the server to other internal or external resources by manipulating user-supplied input to target domains or resources.

## Common SSRF Scenarios

**Fetching Internal Resources:**
Attackers exploit SSRF to access sensitive internal URLs (e.g., /admin, /config, /debug) and gather unauthorized information.

*Example:*
Suppose a web application allows users to input a URL to fetch data from a given website. An attacker could manipulate this input and make the server fetch sensitive internal URLs, such as http://localhost/admin, which may reveal sensitive information.

**Accessing Backend APIs:**
Attackers force the server to interact with internal APIs, potentially exposing sensitive data or performing unauthorized actions.

*Example:*
A web application processes user-uploaded images and makes a request to an image processing API. An attacker can manipulate the URL to target an internal API, which might provide access to critical backend systems or databases.

**Port Scanning of Internal Systems:**
Attackers use SSRF to scan internal IP addresses and identify active services and open ports, aiding in further attacks.

*Example:*
The web application allows users to enter a URL to fetch a webpage's title for display. An attacker manipulates the URL to access an internal IP address and port (e.g., http://192.168.0.1:22) to check for open SSH port (22) and identify active services.

**Bypassing Firewall Restrictions:**
Attackers use SSRF to access resources that are blocked by the firewall, evading security controls.

*Example:*
An attacker can exploit SSRF to bypass firewall restrictions by making the server request an external URL that is blocked for direct access from the internet. Still, the server can access it due to internal network access.

## Impact of SSRF Attacks

- **Unauthorized Data Access:**
   Attackers can read sensitive data from internal systems or databases accessible by the server, leading to potential data breaches.

- **Service and System Compromise:**
   SSRF can compromise backend services and internal systems, allowing attackers unauthorized control over critical components.

- **Information Disclosure:**
   Attackers may leak sensitive information from internal resources or backend APIs, potentially harming the organization's reputation.

- **Application and Server Misuse:**
   SSRF can be leveraged to perform unauthorized actions on other web applications or servers, causing disruptions.

## SSRF Attack Vectors

1. **URL Parameter Manipulation:**
   Attackers manipulate URL parameters to control the target of the SSRF request, directing it to a vulnerable resource.

   *Example SSRF Payload:*

http://vulnerable-server.com/fetch?url=http://internal-server.com/confidential-data


2. **URI Redirection:**
Attackers use URL redirection to trick the server into making requests to unintended destinations, bypassing security controls.

*Example SSRF Payload:*
http://vulnerable-server.com/fetch?url=http://metadata-server/latest/meta-data/iam/security-credentials/admin-role


3. **DNS Rebinding:**
Attackers exploit DNS caching to make the server request a malicious domain after the initial request, leading to SSRF.

*Example SSRF Payload:*
http://vulnerable-server.com/fetch?url=http://attacker.com (where attacker.com resolves to internal-server.com)


4. **URL Shorteners and Redirects:**
Attackers use URL shorteners or redirects to hide the ultimate destination of the SSRF request, making detection challenging.

*Example SSRF Payload:*

http://vulnerable-server.com/fetch?url=http://short.link/malicious


5. **Protocol and Port Abuse:**
Attackers specify non-standard protocols or ports in SSRF requests to evade security measures.

*Example SSRF Payload:*

http://vulnerable-server.com/fetch?url=gopher://internal-server.com/confidential-data


## Real-World SSRF Examples


1. **Reading Local Files:**
Attackers use SSRF to access sensitive files on the server's local file system, such as configuration files containing credentials.

*Example SSRF Payload:*
http://vulnerable-server.com/fetch?url=file:///etc/passwd


2. **Accessing Metadata Endpoints:**
By exploiting SSRF, attackers can access metadata endpoints in cloud environments to gather sensitive information about the infrastructure.

*Example SSRF Payload:*
http://vulnerable-server.com/fetch?url=http://metadata-server/latest/meta-data/iam/security-credentials/admin-role

3. **Attacking Backend Services:**
Attackers exploit SSRF to send malicious requests to internal microservices or APIs, causing service disruptions or data leaks.

*Example SSRF Payload:*
http://vulnerable-server.com/fetch?url=http://internal-api-server.com/admin/deleteUser?userId=123


4. **Exploiting Insecure APIs:**
Attackers can use SSRF to abuse poorly secured external APIs on behalf of the server, leading to potential API misuse.

*Example SSRF Payload:*
http://vulnerable-server.com/fetch?url=http://insecure-api-server.com/changePassword?user=admin&newPassword=hacked123


## Types of SSRF

1. **Blind SSRF:**
SSRF is without direct responses from the server, making it harder to detect, as attackers don't receive immediate feedback on the success of the request.

2. **Time-based SSRF:**
Attackers use delays in responses to determine if the SSRF request was successful or not, enabling them to extract information indirectly.

3. **Asynchronous SSRF:**
Attackers leverage asynchronous behaviour to execute SSRF attacks, making tracing and preventing such attacks more challenging.

4. **DNS SSRF:**
Attackers exploit DNS functionality to perform SSRF, using DNS resolution to access internal resources or bypass filters.

## SSRF Mitigation

- **Input Validation and Allowlisting:**
Validate and restrict user-supplied URLs to prevent SSRF attacks by allowing only trusted domains or IP ranges.

- **Restricting Access to Trusted Domains:**
Configure network settings or firewalls to limit outbound requests to approved destinations, reducing SSRF exposure.

- **URL Parsing and Sanitization:**
Use secure URL parsing libraries and sanitize input to prevent SSRF attacks by blocking malicious URLs.

- **Firewall and Network Configurations:**
Implement strict firewall rules to prevent SSRF attacks from reaching internal resources, limiting the attack surface.

- **Hardening Internal Services:**
Secure internal services to minimize the impact of potential SSRF attacks, ensuring access control and validation.

## Security Best Practices

- **Regular Security Audits:**
Conduct security audits and penetration testing to identify and address SSRF vulnerabilities proactively.

- **Patch Management:**
Keep software and libraries up-to-date to avoid known SSRF-related security issues.

- **Employee Training on SSRF:**
Educate developers and personnel about SSRF risks and prevention strategies to promote a security-aware culture.

- **Secure Coding Guidelines:**
Please follow best practices for secure web application development to avoid SSRF vulnerabilities.

## SSRF Tools and Resources

- **Web Proxies and Debuggers:**
Tools like Burp Suite and OWASP ZAP aid in testing and identifying SSRF vulnerabilities during development.

- **SSRF Testing Frameworks:**
Gopherus, SSRFmap, and Ground-Control provide automated testing capabilities to uncover SSRF vulnerabilities.

- **Exploitation Tools:**
Ruler (For Exchange SSRF) and XXE Injection Frameworks offer tools to exploit SSRF vulnerabilities for testing.

- **OWASP SSRF Cheat Sheet:**
A comprehensive resource from OWASP that guides preventing and mitigating SSRF attacks.

- **Blogs and Research Papers:**
You can learn from SSRF-related blogs and research papers to understand the latest trends and defence strategies.

- **Bug Bounty Platforms and Programs:**
Engage with bug bounty platforms to incentivize researchers to report SSRF vulnerabilities responsibly.

## Recent SSRF Incidents and Case Studies

- **Highlighting Notable Attacks:**
Analyzing actual SSRF attacks helps understand the impact and consequences, raising awareness of the risks.

- **Lessons Learned from Past Incidents:**
Learning from past incidents enhances defence strategies and prepares for similar threats.

## Future Trends in SSRF Defense

- **Evolving Attack Techniques:**
Stay updated on new SSRF attack vectors to adapt defence measures proactively.

- **Advanced Mitigation Strategies:**
Explore emerging technologies and best practices to strengthen SSRF defences and prevent future attacks.
