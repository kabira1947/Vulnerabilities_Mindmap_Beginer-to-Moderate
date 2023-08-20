
**1. Check User Profile Pages for Direct Object References**

Check the User Profile Pages to see if they use direct object references to show user-specific information. Users can find out more about other users, for example, by using URLs with user IDs or other unique identifiers.

Sites can show person profiles with URLs like "www.example.com/user/12345". The attacker uses a fake URL like "www.example.com/user/54321" to get into another person's profile.

**2. Resource-Related Operations**

Resource-Related Operations: Look for features that let you get files, documents, messages, or media or change them. Check to see if changing an object's references gives people without permission access to resources.

Use the URL "www.example.com/document/67890" to access files saved in a document management system. By changing the URL to "www.example.com/document/12345", a hacker gains access to a user's private files.

**3. Account Management**

Account Management: Look at the options for handling your accounts, like changing your email address, changing your password, or deleting your account. Check IDOR for any holes that could let unauthorized users enter or change user or management accounts.

For example, the URL "www.example.com/reset-password?token=abcdef" is the reset token for the password reset feature of a web application. An attacker changes the token to "www.example.com/reset-password?token=123456" to get into another user's account.

**4. Managing User Orders and Shopping Carts**

Managing user orders and shopping carts: Look at the features that control user orders, shopping carts, and saved products. Check to see if you can change the object references to look at or change orders made by other people.

E-commerce websites use URLs like "www.example.com/cart?user=12345" to handle shopping carts. Changing the user ID to "www.example.com/cart?user=54321" lets an attacker see or change another person's cart.

**5. Review Roles, Permissions, and Access Control Policies**

Review the roles, permissions, and access control policies of the program. Check to see if changing object references gets around authorization rules and gives access to unapproved resources.

"www.example.com/thread/12345" is an example of a URL for a web forum. An attacker changes the URL to "www.example.com/thread/54321" to view a limited thread and get around restrictions.

**6. File Upload and Download Functionality**
Check the file upload and download capabilities to see if users can directly view the files they have uploaded through IDOR. Also, check to see if the files you can download contain sensitive information or if there is a way to get around entry restrictions.

The URL "www.example.com/file/67890" is an example of a file-sharing website where users can upload files. A hacker can get into someone else's file by changing the file ID to "www.example.com/file/12345".

**7. API Endpoints**

API Endpoints: Check to see if any object references in the API requests can be changed to give another person access to certain data or functions, even if the program doesn't have API endpoints.

A program may have an API endpoint with the name "api.example.com/user/12345" to get user information. Changing the ID to "api.example.com/user/54321" gives an attacker access to the data of another person.



**Overall,** you can look for IDOR in the parts on URL, GET, PUT, POST, REST API, GraphQL, IDs in Cookies, in Request Handler, and in Some Functions.


**1. URL:** A site for sharing files lets users share files by making their own download URLs. If the platform doesn't have the right access rules in place, an attacker could guess or change the URL to get to other users' files.

**2. GET Parameters:** An e-commerce site's customers can look at the details of their sales by putting the order ID in the URL. Users can change the order ID parameter and see information about other users' sales if the website doesn't have the right access controls.

**3. PUT Parameters:** A content management system lets its users change the information about themselves. If the system doesn't check if the user has permission to change certain fields, an attacker can change the data of other users by making a modified PUT request.

**4. POST request:** Users can submit support tickets through an app by sending a POST request to the server with the necessary information. If the server doesn't do enough authorization checks, an attacker can change the request's ticket ID to look at other users' help tickets.

**5. REST API:** A mobile app authenticates users by using a REST API. If the API doesn't have enough checks for authorization, an attacker could change the user ID in API searches to get into other users' accounts.

**6. GraphQL:** A social media network can use GraphQL to find out details about a user's profile. If the access control methods aren't set up right, an attacker could change the query settings to get private information about other users.

**7. IDs in Cookies:** An online site saves the user's session ID in a cookie. If the website doesn't check the user's permission before giving them access to a piece of content, an attacker could change the session ID saved in a cookie and see other users' private messages or account information.

**8. Request Handler:** A web application uses a request handler to handle file downloads. If the application doesn't do enough authorization checks, an attacker can change the file ID parameter in the request to get access to files belonging to other people.
