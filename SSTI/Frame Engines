## Template Engines for Web Applications

Template Engines are software components or libraries that facilitate the generation of dynamic content for web applications. Web development commonly uses them to separate the presentation layer (HTML templates) from the application logic (server-side code). Template engines allow developers to create reusable templates that contain placeholders for dynamic data. When a request is made to the web application, the template engine processes the template. It replaces the placeholders with actual data before sending the rendered content to the client's browser.

Key functionalities of template engines include:
1. **Placeholder Replacement:** Template engines use placeholders (also known as variables or tags) in the template files to indicate where dynamic data should be inserted. These placeholders are typically represented within curly braces or square brackets, such as `{{ variable_name }}`.
2. **Conditional Statements:** Template engines support conditional statements, such as if-else and loops, which enable developers to control data flow and customize the content based on certain conditions.
3. **Template Inheritance:** Many template engines support template inheritance, where developers can create a base template with common elements (e.g., header, footer) and extend or override specific sections in child templates. This promotes code reusability and maintainability.
4. **Output Escaping:** Template engines often provide built-in mechanisms for output escaping. This helps prevent XSS (Cross-Site Scripting) attacks by automatically encoding user-supplied data before rendering it in the template.
5. **Filters and Transformations:** Some template engines offer filters or transformations that allow developers to manipulate the data before inserting it into the template—for example, formatting dates or converting text to uppercase.

### Examples of Template Engines:

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
