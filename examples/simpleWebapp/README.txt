Simple Web Application Demo
===========================

This demo shows how to build and deploy an SSO protected using Apache CXF Fediz
web application.

The Demo consist of three parts:

- Configure Fediz in the IDP and RP Tomcat instances
- Install the Fediz Identity Provider (IDP)
- Build the Demo Web Application

Please review the README in the samples main directory before continuing.

Configure Tomcat instances used for RP and IDP
----------------------------------------------
The Tomcat installation holding the relying parties (the demo Web application
for this sample) must be configured properly before applications can be
deployed to it.  See this wiki page for instructions:
http://cxf.apache.org/fediz-tomcat.html

Copy the Fediz Configuration file into the directory 'conf' of the Tomcat-RP
installation. The configuration file is located in 
src/main/config/fediz_config.xml of this example.  This configuration
references the java keystore 'tomcat-rp.jks' from examples/samplekeys
which contains the STS' public certificate to validate a SAML token
issued by the IDP/STS.

It's also assumed the separate Tomcat instance hosting the Fediz IDP and IDP
STS has been configured and is running as described here:  
http://cxf.apache.org/fediz-idp.html.  To confirm the STS is working,
check that the WSDL is viewable from the browser using the URL given
on that page.


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


Deploying the demo to Tomcat
----------------------------
You can manually copy the generated WAR file to the Tomcat-RP's webapps folder, 
or use the Tomcat Maven Plugin as described in the README file in the example folder
root.


Test the demo
-------------
Enter the following URL into the browser (TCP port depends on your HTTP settings):

https://localhost:8443/fedizhelloworld/secure/fedservlet

The browser is redirected to the IDP and prompts for username and password. As described
in the IDP installation, the following users are already set up:

User: alice   Password: ecila
User: bob     Password: bob
User: ted     Password: det


