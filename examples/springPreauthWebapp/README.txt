Simple Spring (Pre-Authentication) Web Application Demo
=======================================================

This demo shows how to build and deploy an SSO protected using Apache CXF Fediz
web application where WS-Federation based login is managed by the container but
Fediz initializes the Spring Security Context which provides a richer security
API and configuration than the Java Servlet API.

This example still requires the fediz plugin be configured on the container level
whereas the demo 'springWebapp' can be deployed into any application server as
fediz is integrated into spring security natively.

The Spring Security reference documentation provides more background information
about Pre-Authentication support in Spring Security:
http://static.springsource.org/spring-security/site/docs/3.2.x/reference/springsecurity-single.html#preauth

Running this sample consists of four steps:

- Configure the Tomcat-IDP and Tomcat or Jetty-RP instances
- Building the demo using Maven
- Deploying the demo to the RP instance
- Testing the demo

Please review the README in the samples main directory before continuing.

Configure the Tomcat-IDP
------------------------
Make sure the separate Tomcat instance hosting the Fediz IDP and IDP
STS has been configured and is running as described here:  
http://cxf.apache.org/fediz-idp.html.  Confirm the STS is active by
checking that the WSDL is viewable from the browser using the URL given
on that page--don't proceed further unless it is.


a) Configure the Tomcat-RP instance
-----------------------------------
Tomcat installation holding the relying parties (the demo Web application
for this sample) must be configured properly before applications can be
deployed to it.  See this wiki page for instructions:
http://cxf.apache.org/fediz-tomcat.html -- the "Installation" and "HTTPS
Configuration" sections are the only parts that need configuration for this
sample. 

b) Configure the Jetty-RP instance
----------------------------------
Jetty installation holding the relying parties (the demo Web application
for this sample) must be configured properly before applications can be
deployed to it.  See this wiki page for instructions:
http://cxf.apache.org/fediz-jetty.html -- the "Installation" and "HTTPS
Configuration" sections are the only parts that need configuration for this
sample. 

Demo Web Application
---------------------
The main code lives in the class FederationServlet. This Servlet is protected
and can be accessed only if the browser user is authenticated. The purpose of
the FederationServlet is to illustrate the usage of the Java Servlet Security
API to get the authenticated user and to check the roles he has. Further, 
the FederationServlet shows how to access claims data (user data) which were 
stored in the SAML token by using the Fediz interface FederationPrincipal.
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


a) Deploying the demo to Tomcat
-------------------------------
First copy this sample's Fediz Configuration file (src/main/config/fediz_config.xml)
into the Tomcat-RP's conf folder.  This configuration references the 
Java keystore 'tomcat-rp.jks' available in Fediz' examples/samplekeys folder 
but should already be in the Tomcat RP's root folder when you configured this
instance as stated in the prerequisites.

Then, either manually copy this sample's generated WAR file to the Tomcat-RP's 
webapps folder, or use the Tomcat Maven Plugin as described in the README file 
in the example folder root.

b) Deploying the demo to Jetty
------------------------------
First copy this sample's Fediz Configuration file (src/main/config/fediz_config.xml)
into the Jetty-RP's etc folder.  This configuration references the 
Java keystore 'tomcat-rp.jks' available in Fediz' examples/samplekeys folder 
but should already be in the Jetty RP's root folder when you configured this
instance as stated in the prerequisites.

Then, either manually copy this sample's generated WAR file to the Jetty-RP's 
webapps folder, or use the Jetty Maven Plugin as described in the README file 
in the example folder root.


Test the demo
-------------
Enter the following URL into the browser (TCP port depends on your HTTP settings):

https://localhost:8443/fedizhelloworld/secure/fedservlet

The browser is redirected to the IDP and prompts for username and password. As described
in the IDP installation, the following users are already set up:

User: alice   Password: ecila
User: bob     Password: bob
User: ted     Password: det


