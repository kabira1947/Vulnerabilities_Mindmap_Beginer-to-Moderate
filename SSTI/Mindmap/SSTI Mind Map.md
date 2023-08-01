# SSTI

## Definition

### Server-Side Template Injection (SSTI) is a web application vulnerability.

Attacker injects malicious code into server-side templates.

Unvalidated user input treated as code by the template engine.

Results in execution of injected payload on the server.


## Impact of SSTI

### Remote Code Execution (RCE).

Server Takeover.

Unauthorized Data Access.

Disruptions and Outages.

Escalation to Other Attacks.

Compliance and Legal Consequences.

## Template Engine

### Key functionalities of template engines.

Placeholder Replacement.

Conditional Statements.

Template Inheritance.

Output Escaping.

Filters and Transformations.
Examples: Handlebars, EJS, Freemarker.


## Vulnerability Cause

### Insufficient Input Validation.

Lack of Output Escaping.

Dynamic Template Generation.

Usage of Complex Templating Engines.

Failure to Implement Security 

Frequent Template Customization.

Lack of Security Awareness.

## Types of SSTI Attacks

### Input Concatenation

### Lack of Output Escaping 

## Tools

### SAST Tools

- SonarQube

FindBugs

ESLint


### DAST Tools

- OWASP ZAP

Burp Suite

Acunetix

TPLmap (Discontinued in 2018 but still working in 2023) 

TPLmap also has a burp extension in external download (Github) 

## How to Execute the Attack

### Understand the Template Syntax

### Craft Malicious Pqyloads

### Identity Context Awareness

## Preventive Measures

### Input Validation.

Contextual Output Escaping.

Use Secure Template Engines.

Implement Whitelisting.

Disable Code Evaluation.

Strict Template Access Control.

Content Security Policies (CSP).

Regular Security Audits.

Security Training.

Follow Security Guidelines.

Implement Web Application Firewall (WAF).

Keep Software Up to Date.

Least Privilege Principle.


## Current Trends in SSTI

### Increased Awareness

### Complex Template Engines

### Third Party Libraries

### Template Language Features

### Advanced payload Obfuscation

## Best Practices

### Stay Informed

### Regular Security Testing

### Security Awareness and Training

