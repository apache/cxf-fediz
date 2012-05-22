Web Service Client Web Application Demo
=======================================

This demo shows a more complext scenario where a Web Application is deployed as in the example 'simpleWebapp'.
The difference is that this demo Web Application calls a Web Services which is protected by a SAML token which
must be issued by a Security Token Service (STS). The STS is part of the Fediz Identity Provider (IDP).
The Web Application requests a SAML token for the Web Service *on behalf of* the user who logged into the 
Web Application. Finally, the Web Service knows which browser user triggered the Web Service call.

The Demo consist of three parts:

- Enable Fediz in Servlet Container (ex. Tomcat)
- Install the Fediz Identity Provider (IDP)
- Build the Demo Web Application
- Build the Demo Web Service


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

The main code lives in the class FederationServlet. This class has been extended by an implementation of the method doPost().
The doGet implementation is the same as in the demo 'simpleWebapp'.
The Web Application contains a service.jsp which provides a button to trigger the Web Service call which is in the
doPost implementation. CXF requests a SAML token from the STS on behalf of the security token used during the
Web Application Login before sending the SOAP request to the Web Service.

The FederationServlet prints the String returned from the Web Service (which is the authenticated Browser user).

There is not security related programming required. CXF processes the information in the Spring configuration and
the policy document and enforces that.


Demo Web Service
---------------------

The main and only code lives in the class GreeterImpl. It reads the authenticated principal from the JAX-WS WebServiceContext
and returns the principal name to the Web Service Client (Web Application).

The interesting pieces are in beans.xml and the WS-SecurityPolicy definition in the WSDL hello_world.wsdl.

There is no security related programming required. CXF processes the information in the Spring configuration and
the policy document and enforces that.


More details are provided on this blog:
http://owulff.blogspot.com/2012/04/sso-across-web-applications-and-web_16.html


Prerequisite
------------
Please review the README in the samples main directory before continuing.
It's recommended to run the demo simpleWebapp first as this is an extended demo.


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

It's recommended to deploy the Web Service into a different Container instance than the Web Application.


Test the demo
-------------

Enter the following URL into the browser (TCP port depends on your HTTP settings):

1)
https://localhost:8443/fedizhelloworld/secure/fedservlet

The browser is redirected to the IDP and prompts for username and password. As described in the IDP installation,
the following users are already set up:

User: alice   Password: ecila
User: bob     Password: bob
User: ted     Password: det

2)
https://localhost:8443/fedizhelloworld/secure/service.jsp

Click "Call Service"

Your authenticated user must be printed again.


Using Eclipse to run and test the demo
--------------------------------------

run the following in the demo base directory

mvn eclipse:eclipse

Then use Import / Existing projects into workspace and browse to the wsclientWebapp directory. Import the project.

