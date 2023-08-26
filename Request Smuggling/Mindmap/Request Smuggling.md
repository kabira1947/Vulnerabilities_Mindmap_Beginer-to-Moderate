# Request Smuggling

## Definition

### Vulnerability

- Request smuggling occurs due to discrepancies in how front-end and back-end servers interpret HTTP requests, leading to inconsistencies in processing.

### Causes

- Implementation inconsistencies in HTTP specifications across web application architecture components (load balancers, caching servers, proxies).

### Exploitation

- Manipulation of headers like Content-Length and Transfer-Encoding to trick servers into interpreting requests differently.

## Types of Request Smuggling

### 1.	CL.TE Request Smuggling



- 1.	Manipulating Content-Length to send multiple requests in a single HTTP request.

### 2.	TE.CL Request Smuggling:






- Confusing front-end and back-end servers by mixing Transfer-Encoding: chunked and Content-Length headers.

### 3.	TE.TE Request Smuggling (Multiple Transfer-Encoding headers)



- The front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

### 4.	CL.CL Request Smuggling (
Multiple Content-Length headers)

- CL.CL Request Smuggling entails sending multiple Content-Length headers, causing servers to potentially misinterpret them, leading to request boundary confusion and potential unauthorized actions by attackers.

## Unserdtand the Terms and Working


### 1.	HTTP/1.0 vs. HTTP/1.1


- HTTP/1.1 is an updated version of HTTP/1.0 with improvements in persistent connections, caching, and host header support, leading to faster and more efficient web communication.

### 2.	Connection: Keep-Alive vs. Close

- Keep-Alive allows the reuse of the same TCP connection for multiple HTTP requests, while Close terminates the connection after each request-response cycle.

### 3.	Chunked transfer encoding

- Chunked transfer encoding transfers data in variable-sized chunks, enabling progressive data transmission and efficient handling of large payloads without knowing the total size beforehand.

## Process or Technique to Attack

### Connection Splitting

- Sending multiple requests in a single TCP connection, interpreted differently by front-end and back-end servers.

### HTTP/1.0 Smuggling

- Exploiting inconsistencies between front-end and back-end servers in handling HTTP/1.0 requests.

### HTTP/2 Smuggling

- Abusing HTTP/2's multiplexing to confuse front-end and back-end servers in request interpretation.

### WebSocket Hijacking


- 1.	Manipulating WebSocket frame headers to confuse front-end servers about the number and boundaries of requests.

## Types of Request Smuggling Vulns

### 1.	HTTP Request Smuggling via Content-Length Header


- Exploiting inconsistencies between front-end and back-end servers to manipulate request boundaries using the Content-Length header.

### 2.	HTTP Request Smuggling via Transfer-Encoding Header

- Manipulating backend parsing by using the Transfer-Encoding header to create confusion in request handling.

### 3.	HTTP Request Smuggling via HTTP Verb Tunnelling:


- Tricking front-end and back-end servers to interpret request methods differently, leading to unauthorized actions.


### 4.	HTTP Request Smuggling via HTTP Pipelining:


- Exploiting pipelined requests to cause discrepancies in how front-end and back-end servers interpret and process the requests.


### 5.	HTTP Request Smuggling via Server-side Parsing Differences:


- Leveraging differences in how the front-end and back-end servers parse request headers to bypass security mechanisms.


### 6.	Request Smuggling with Unicode Encoding


- Using Unicode encoding to obfuscate the request, leading to inconsistent interpretations by front-end and back-end servers.


### 7.	Request Smuggling via HTTP Header Injection


- Injecting rogue headers to manipulate request processing and cause discrepancies between front-end and back-end servers.

## Tools


### 1.	Request Smuggling scanner using BURP

### 2.	Smuggler by defparam 

### Http2Smugl

## Impacts can Lead to Vulnerabilities

### 1.	Cache poisoning

### 2. HTTP response splitting

### 3.	Unauthorized access

### 4.	Cross-Site Request Forgery (CSRF)

### 5.	Server-side request forgery (SSRF)

### 6.	SQL injection

### 7.	Remote File Inclusion (RFI):

### 8. Command Injection

### 9.	XML External Entity (XXE) Injection

### 10.	Remote Code Execution (RCE)

### 11.	Data exposure and leakage

## Recent Real-World Examples

### 1.	HTTP Request Smuggling in AWS Elastic Load Balancer

- Exploited inconsistencies in AWS ELB, potentially bypassing security measures.


### 2. HTTP Desync Attack on Apache Tomcat

- 1.	Affected widely-used Apache Tomcat server, leading to unauthorized access or code execution

### Citrix NetScaler ADC Request Smuggling

- Vulnerability in Citrix NetScaler ADC allowed unauthorized access and code execution.

### Microsoft IIS Request Smuggling

- 1.	A vulnerability in the IIS server allowed HTTP request smuggling attacks, potentially enabling unauthorized access or code execution.

## Mitigations

1.	Use a secure load balancer/proxy server

2.	Properly Configure proxy servers  . Configure the front-end server to exclusively use HTTP/2 to communicate with back-end systems, as this protocol prevents ambiguity within the boundaries between requests.


3.	Disable the Reuse of Back-end connections so that each back-end request is sent over a separate network connection.

4.	Use the same web server software with the same configuration for the front-end and back-end servers.

5.	Implement proper request parsing adhering to HTTP standards.

6.	Deploy a Web Application Firewall (WAF) to detect and block smuggling attacks.

7.	Keep server and proxy software up to date

8.	Validate and sanitize user input.

9.	Implement proper error handling and detailed logging.

10.	Follow secure coding practices and conduct regular security audits.

11.	Educate developers and administrators about request smuggling attacks and secure coding.


## Future Trends

### 1.	Increased awareness among organizations about request smuggling vulnerabilities.

2.	Rise in public disclosures by security researchers and bug bounty programs.

3.	Continuous research to discover new variations and attack vectors.

4.	Vendors working on security patches and updates.

5.	Regulatory requirements focusing on web application security.

6.	Incorporation of detection capabilities in security testing tools.

7.	Industry collaboration for information sharing and best practices.


