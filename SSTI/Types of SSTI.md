## Types of SSTI Vulnerabilities:

a. **Input Concatenation Vulnerability:**
This type of SSTI vulnerability occurs when user input is directly concatenated into templates without proper validation or sanitization. Attackers can exploit this vulnerability by injecting malicious code or payloads into the template, which is then executed server-side.

**Practical Example Scenario:**
A web application uses a template engine that allows user customization of email templates. The application will enable users to input their name, which is then directly concatenated into the email template without proper validation.

**Vulnerable Code:**

```html
<html>
<head>
    <title>Welcome Email</title>
</head>
<body>
    <p>Dear {{ user_input_name }},</p>
    <p>Welcome to our website!</p>
</body>
</html>
```

**Exploitation:**
An attacker could input malicious code as their name, like "{{ 7 * 7 }}", resulting in the following template after rendering:

```html
<html>
<head>
    <title>Welcome Email</title>
</head>
<body>
    <p>Dear 49,</p>
    <p>Welcome to our website!</p>
</body>
</html>
```

In this case, the malicious payload "{{ 7 * 7 }}" is executed server-side, leading to "Dear 49" in the email, demonstrating successful exploitation.

b. **Lack of Output Escaping Vulnerability:**
When web applications fail to escape user input before rendering it in templates, it can lead to SSTI vulnerabilities. Attackers can inject malicious code to be executed when the template is rendered, allowing them to manipulate the template engine.

**Practical Example Scenario:**
A web application uses a template engine to generate dynamic product listings on an e-commerce site. The application fails to escape user input before rendering it in the template.

**Vulnerable Code:**

```html
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
```

**Exploitation:**
An attacker could inject a malicious script as the product name:

```html
<script>alert("XSS Attack!");</script>
```

When a user views the product page, the injected script will be executed as part of the template rendering, resulting in a pop-up alert with "XSS Attack!".

