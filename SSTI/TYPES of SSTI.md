2.	TYPES of SSTI Vulnerabilities:
a.	Input Concatenation Vulnerability: This type of SSTI vulnerability occurs when user input is directly concatenated into templates without proper validation or sanitization. Attackers can exploit this vulnerability by injecting malicious code or payloads into the template, which is then executed server-side.
Practical Example Scenario: 
A web application uses a template engine that allows user customization of email templates. The application will enable users to input their name, which is then directly concatenated into the email template without proper validation.

Vulnerable Code:

<html>
<head>
    <title>Welcome Email</title>
</head>
<body>
    <p>Dear {{ user_input_name }},</p>
    <p>Welcome to our website!</p>
</body>
</html>

Exploitation: An attacker could input malicious code as their name, like "{{ 7 * 7 }}", resulting in the following template after rendering:

<html>
<head>
    <title>Welcome Email</title>
</head>
<body>
    <p>Dear 49,</p>
    <p>Welcome to our website!</p>
</body>
</html>

In this case, the malicious payload "{{ 7 * 7 }}" is executed server-side, leading to "Dear 49" in the email, demonstrating successful exploitation.


b.	Lack of Output Escaping Vulnerability: When web applications fail to escape user input before rendering it in templates, it can lead to SSTI vulnerabilities. Attackers can inject malicious code to be executed when the template is rendered, allowing them to manipulate the template engine.

Practical Example Scenario: 
A web application uses a template engine to generate dynamic product listings on an e-commerce site. The application fails to escape user input before rendering it in the template.


Vulnerable Code:

<!DOCTYPE html>
<html>
<head>
    <title>{{ product_name }}</title>
</head>
<body>
    <h1>{{ product_name }}</h1>
    <p>Description: {{ product_description }}</p>
</body>
</html>

Exploitation: 
An attacker could inject a malicious script as the product name:

<script>alert("XSS Attack!");</script>

When a user views the product page, the injected script will be executed as part of the template rendering, resulting in a pop-up alert with "XSS Attack!".


Types of SSTI Attacks:
a.	Remote Code Execution (RCE): The most severe impact of SSTI vulnerabilities is the ability of attackers to achieve remote code execution on the server. By injecting malicious payloads into templates, attackers can gain full control of the backend servers and execute arbitrary code.

Example Scenario:
Suppose a web application allows users to customize their profile page by providing a template with dynamic content using a template engine. The application fails to properly validate and sanitize the user's template input, which creates an SSTI vulnerability.

Vulnerable Code:

<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
</head>
<body>
    <h1>Hello, {{ user_input_name }}!</h1>
    {{ user_input_template }}
</body>
</html>

Exploitation:
An attacker crafts a malicious payload in the user's template input:
{{ 7 * 7 }}

When the profile page of the targeted user is viewed, the malicious payload will be executed server-side. This results in the following output:
Hello, User!
49

In this case, the payload {{ 7 * 7 }} is executed as code on the server, leading to the arithmetic operation and the value 49 being rendered on the profile page.


b.	Server Takeover: In cases where RCE is achieved, attackers can use the compromised server to launch additional attacks on internal infrastructure or gain unauthorized access to sensitive data and files.

Example Scenario:
Imagine a blogging platform that allows users to create custom blog templates using a template engine. The platform does not adequately validate and escape the user's input, leading to an SSTI vulnerability.

Vulnerable Code:

<!DOCTYPE html>
<html>
<head>
    <title>{{ user_input_title }}</title>
</head>
<body>
    <h1>{{ user_input_title }}</h1>
    {{ user_input_content }}
</body>
</html>

Exploitation:
An attacker exploits the SSTI vulnerability by injecting malicious code into the blog template:

{{ config['SECRET_KEY'] }}

When a visitor views the malicious blog post, the attacker gains access to the server's configuration data, including sensitive information like the application's secret key. This information can then be used to launch further attacks and compromise the server.

c.	Data Leakage: Even when remote code execution is impossible, attackers may still be able to read sensitive data or files stored on the server. This can lead to the exposure of confidential information.

Example Scenario:
Suppose an online store uses a template engine to generate product pages. The application fails to properly validate and escape user input in the product templates, leading to an SSTI vulnerability.

Vulnerable Code:

<!DOCTYPE html>
<html>
<head>
    <title>{{ product_name }}</title>
</head>
<body>
    <h1>{{ product_name }}</h1>
    <p>Description: {{ product_description }}</p>
</body>
</html>

Exploitation:
An attacker injects malicious code into the product description:

{{ file_read('/etc/passwd') }}

When a user views the product page, the attacker gains access to the contents of the /etc/passwd file. This could potentially expose sensitive information about system users.

d.	Escalation of Privileges: Depending on the application's context, successful SSTI attacks might allow attackers to escalate their privileges and access functionalities or resources they should not have.

Example Scenario:
Consider an application where users can create and share dynamic email templates using a template engine. The application fails to validate and sanitize user input in the template creation process, creating an SSTI vulnerability.

Vulnerable Code:

<!DOCTYPE html>
<html>
<head>
    <title>Email Template</title>
</head>
<body>
    <h1>Hello, {{ user_input_name }}!</h1>
    <p>{{ user_input_template }}</p>
</body>
</html>

Exploitation:
An attacker injects a malicious payload in the template:

{{ user.isAdmin() }}

When an email is sent using the malicious template, the payload executes on the server, and the attacker gains information about the user's privileges. If the payload returns true, indicating that the user is an admin, the attacker may gain unauthorized access to admin-only functionalities or sensitive resources.
