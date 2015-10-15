JAX-RS Spring Security Web Application Demo
==================================

This demo shows how to build and deploy an SSO protected JAX-RS web application
using Apache CXF Fediz and Spring Security.

The demo uses Apache CXF CXFServlet and CXF JAX-RS Endpoint Spring declarations.
If you work with Jersey or RESTEasy - please replace CXF specific Servlet and Spring declarations with your preferred JAX-RS implementation's Servlet and Spring declarations. The application code 
is a portable JAX-RS code. 

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


Demo Web Application
--------------------
The main code lives in the class FederationService. This JAX-RS Service is protected
and can be accessed only if the browser user is authenticated. The purpose of
the FederationService is to illustrate the usage of the Java Servlet Security
API to get the authenticated user and to check the roles he has. Further, 
the FederationService shows how to access claims data (user data) which were 
stored in the SAML token by using the Fediz interface FedizPrincipal.
Beyond that, the FederationService illustrates how to access the SAML token
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


