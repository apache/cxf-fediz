Simple Web Application Demo
===========================

This demo shows how to build and deploy an SSO protected using Apache CXF Fediz web application.

The Demo consist of three parts:

- Enable Fediz in Servlet Container (ex. Tomcat)
- Install the Fediz Identity Provider (IDP)
- Build the Demo Web Application


Fediz configuration in Tomcat
-----------------------------

The Tomcat installation must be updated before a Web Application can be deployed.

The following wiki page gives instructions how to do that:
http://cxf.apache.org/fediz-tomcat.html


Fediz Identity Provider (IDP)
-----------------------------

The IDP is the central security server to whom unauthenticated requests are redirected. Its responsibility is
to authenticate the browser user and issue a security token which fulfills the Web Application requirements.

The following wiki page gives instructions how to set up the IDP:
http://cxf.apache.org/fediz-idp.html


Demo Web Application
---------------------

The main code lives in the class FederationServlet. This Servlet is protected and can only be accessed if the
browser user is authenticated. The purpose of the FederationServlet is to illustrate the usage of the
Java Servlet Security API to get the authenticated user and to check the roles he has.
Further, the FederationServlet shows how to access claims data (user data) which were store in the SAML token
by using the Fediz interface FederationPrincipal.
Beyond that, the FederationServlet illustrates how to access the SAML token if required. The classes 
SecurityTokenThreadLocal.java and FederationFilter.java can be used to achieve that. You could get this information
directly from the HTTP session.


Prerequisite
------------
Please review the README in the samples main directory before continuing.


Building the demo using Maven
-----------------------------

From the base directory of this sample (i.e., where this README file is
located), the pom.xml file is used to build and run the demo. 

Using either UNIX or Windows:

  mvn clean install   (builds the demo and creates a WAR file for Servlet deployment)


Deploying the demo to Tomcat
----------------------------

You can manually copy the generated WAR file to the Tomcat webapps folder, or, if you
have Maven and Tomcat set up to use the Tomcat Maven Plugin (http://mojo.codehaus.org/tomcat-maven-plugin/)
you can use the mvn tomcat:redeploy command instead.  Important: if you're using this 
command, and are using Tomcat 6 instead of Tomcat 7, update the tomcat-maven-plugin configuration 
in the pom.xml, switching to the the Tomcat 6-specific "url" element.


Test the demo
-------------

Enter the following URL into the browser (TCP port depends on your HTTP settings):

https://localhost:8443/fedizhelloworld/secure/fedservlet

The browser is redirected to the IDP and prompts for username and password. As described in the IDP installation,
the following users are already set up:

User: alice   Password: ecila
User: bob     Password: bob
User: ted     Password: det


Using Eclipse to run and test the demo
--------------------------------------

run the following in the demo base directory

mvn eclipse:eclipse

Then use Import / Existing projects into workspace and browse to the simpleWebapp directory. Import the project.

