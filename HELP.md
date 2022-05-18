# Read Me First
The following was discovered as part of building this project:

* The original package name 'io.ysf.spring-security-jwt' is invalid and this project uses 'io.ysf.springsecurityjwt' instead.

# Getting Started

### Reference Documentation
For further reference, please consider the following sections:

* [Official Apache Maven documentation](https://maven.apache.org/guides/index.html)
* [Spring Boot Maven Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/2.6.7/maven-plugin/reference/html/)
* [Create an OCI image](https://docs.spring.io/spring-boot/docs/2.6.7/maven-plugin/reference/html/#build-image)
* [Spring Web](https://docs.spring.io/spring-boot/docs/2.6.7/reference/htmlsingle/#boot-features-developing-web-applications)
* [Spring Security](https://docs.spring.io/spring-boot/docs/2.6.7/reference/htmlsingle/#boot-features-security)

### Guides
The following guides illustrate how to use some features concretely:

* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)
* [Serving Web Content with Spring MVC](https://spring.io/guides/gs/serving-web-content/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/bookmarks/)
* [Securing a Web Application](https://spring.io/guides/gs/securing-web/)
* [Spring Boot and OAuth2](https://spring.io/guides/tutorials/spring-boot-oauth2/)
* [Authenticating a User with LDAP](https://spring.io/guides/gs/authenticating-ldap/)



http://localhost:9193/authenticate
{"username":"admin","password":"pass"}
https://www.bezkoder.com/spring-boot-security-login-jwt/
https://www.youtube.com/watch?v=X80nJ5T7YpE&t=58s

Methods	Urls	Actions
POST	/api/auth/signup	signup new account
POST	/api/auth/signin	login an account
POST	/api/auth/signout	logout the account
GET	/api/test/all	retrieve public content
GET	/api/test/user	access User’s content
GET	/api/test/mod	access Moderator’s content
GET	/api/test/admin	access Admin’s content


---
http://localhost:9193/api/auth/signup
{
    "username": "smanasa1",
    "password": "newuser1",
    "email": "sm1@test.com",
    "role": ["admin","mod"]
}
http://localhost:9193/api/auth/signin
{
    "username": "smanasa1",
    "password": "newuser1"
}


http://localhost:9193/api/auth/signincode
{
    "code": "200139"
}

https://www.bezkoder.com/spring-boot-react-redux-example/