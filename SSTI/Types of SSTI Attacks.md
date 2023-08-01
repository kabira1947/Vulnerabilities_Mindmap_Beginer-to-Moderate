## Types of SSTI Attacks:

a. **Remote Code Execution (RCE):**
The most severe impact of SSTI vulnerabilities is the ability of attackers to achieve remote code execution on the server. By injecting malicious payloads into templates, attackers can gain full control of the backend servers and execute arbitrary code.

**Example Scenario:**
Suppose a web application allows users to customize their profile page by providing a template with dynamic content using a template engine. The application fails to properly validate and sanitize the user's template input, which creates an SSTI vulnerability.

**Vulnerable Code:**

```html
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
```

**Exploitation:**
An attacker crafts a malicious payload in the user's template input:
{{ 7 * 7 }}

When the profile page of the targeted user is viewed, the malicious payload will be executed server-side. This results in the following output:
Hello, User!
49

In this case, the payload {{ 7 * 7 }} is executed as code on the server, leading to the arithmetic operation and the value 49 being rendered on the profile page.

b. **Server Takeover:**
In cases where RCE is achieved, attackers can use the compromised server to launch additional attacks on internal infrastructure or gain unauthorized access to sensitive data and files.

**Example Scenario:**
Imagine a blogging platform that allows users to create custom blog templates using a template engine. The platform does not adequately validate and escape the user's input, leading to an SSTI vulnerability.

**Vulnerable Code:**

```html
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
```

**Exploitation:**
An attacker exploits the SSTI vulnerability by injecting malicious code into the blog template:

```html
{{ config['SECRET_KEY'] }}
```

When a visitor views the malicious blog post, the attacker gains access to the server's configuration data, including sensitive information like the application's secret key. This information can then be used to launch further attacks and compromise the server.

c. **Data Leakage:**
Even when remote code execution is impossible, attackers may still be able to read sensitive data or files stored on the server. This can lead to the exposure of confidential information.

**Example Scenario:**
Suppose an online store uses a template engine to generate product pages. The application fails to properly validate and escape user input in the product templates, leading to an SSTI vulnerability.

**Vulnerable Code:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>{{ product_name }}</title>
</head>
<body>
    <h1>{{ product_name }}</h1>
    <p>Description: {{ product_description }}</p

