Simple Spring Web Application Demo
==================================

This demo shows how to build and deploy an SSO protected web application
using Apache CXF Fediz. The web application uses spring security 2 for
authentication and authorization natively which provides a richer security
API and configuration than the Java Servlet API.

If you still want to enforce security on the container level but want to use
spring security's features the demo 'springPreAuthWebapp' illustrates that.

Running this sample consists of four steps:

- Configure the Tomcat-IDP and Servlet Container for RP instances
- Building the demo using Maven
- Deploying the demo to the RP instance
- Testing the demo

Please review the README in the samples main directory before continuing.

Configure the Tomcat-IDP and Servlet Container for RP instances
---------------------------------------------------------------
First, make sure the separate Tomcat instance hosting the Fediz IDP and IDP
STS has been configured and is running as described here:  
http://cxf.apache.org/fediz-idp.html.  Confirm the STS is active by
checking that the WSDL is viewable from the browser using the URL given
on that page--don't proceed further unless it is.

The benefit of using Spring Security 2 which is packaged with the demo application
there are no plugin deployments required for the RP Servlet Container. 
See this wiki page for instructions:
http://cxf.apache.org/fediz-spring-2.html -- the "HTTPS Configuration" sections
are the only parts that need configuration for this sample. 


Demo Web Application
--------------------
The main code lives in the class FederationServlet. This Servlet is protected
and can be accessed only if the browser user is authenticated. The purpose of
the FederationServlet is to illustrate the usage of the Spring Security 2 API and
Configuration to get the authenticated user and to check the roles he has. Further, 
the FederationServlet shows how to access claims data (user data) which were 
stored in the SAML token by using the Fediz interface FedizPrincipal.
Beyond that, the FederationServlet illustrates how to access the SAML token
if required. The classes SecurityTokenThreadLocal.java and FederationFilter.java
can be used to achieve that. You could get this information directly from the
HTTP session.


Building the demo using Maven
-----------------------------
From the base directory of this sample (i.e., where this README file is
located), the pom.xml file is used to build and run the demo. From a 
command prompt, enter:

  mvn clean install   (builds the demo and creates a WAR file for Servlet deployment)


Deploying the demo to Tomcat
----------------------------
Either manually copy this sample's generated WAR file to the Tomcat-RP's 
webapps folder, or use the Tomcat Maven Plugin as described in the README file 
in the example folder root.
It's recommended to not deploy this WAR into Servlet Container where Fediz is
integrated into the Security Layer of the Container itself.


Test the demo
-------------
Enter the following URL into the browser (TCP port depends on your HTTP settings):

https://localhost:10443/fedizhelloworld/secure/fedservlet

The browser is redirected to the IDP and prompts for username and password. As described
in the IDP installation, the following users are already set up:

User: alice   Password: ecila
User: bob     Password: bob
User: ted     Password: det


