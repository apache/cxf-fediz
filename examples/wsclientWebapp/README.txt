Web Service Client Web Application Demo
=======================================

This demo builds on the simpleWebapp sample to show a Relying Party (RP) web application using an IDP-provided SAML token to access a third-party web service.  Here the IDP authenticates the browser user that the web application requested the token on behalf of, and uses its STS to issue the token which fulfills the web service's security requirements.  From the SAML token the Web Service is informed which browser user triggered the Web Service call.

The Demo consist of three parts:

- Configure Fediz in the IDP and RP Tomcat instances
- Configure Tomcat instance holding the web service provider
- Build/deploy the Demo Web Application
- Build/deploy the Demo Web Service

Please review the README in the samples main directory before continuing.
You may wish to run the simpleWebapp demo first as this is an extended demo.


Configure Tomcat instances used for RP and IDP
----------------------------------------------
The Tomcat installation holding the relying parties (the demo Web application 
for this sample) must be configured properly before applications can be 
deployed to it.  See this wiki page for instructions:
http://cxf.apache.org/fediz-tomcat.html

Copy the Fediz Configuration file into the directory 'conf' of the Tomcat-RP
 installation. The configuration file is located in 
src/main/config/fediz_config.xml of this example.  This configuration
references the java keystore 'tomcat-rp.jks' from examples/samplekeys which
contains the STS' public certificate to validate a SAML token issued by the
IDP/STS.

It's also assumed the separate Tomcat instance hosting the Fediz IDP and IDP
 STS has been configured and is running as described here:  
http://cxf.apache.org/fediz-idp.html.  To confirm the STS is working, check
that the WSDL is viewable from the browser using the URL given on that page.


Configure Tomcat instance used for Web Service Provider
-------------------------------------------------------
To better model a real-world environment the web service provider is hosted
on a third Tomcat instance separate from the RP and IDP Tomcat instances.
You can follow the Tomcat configuration instructions given here for the IDP
Tomcat instance: 
http://cxf.apache.org/fediz-idp.html#FedizIDP-Tomcatserver.xmlconfiguration 
but (1) use Tomcat ports different from the IDP and RP instances, perhaps 
10080 for HTTP, 10443 for HTTPS, and 10005 as the server communication port, 
and (2) don't reuse the Tomcat IDP keystore, the examples/samplekeys folder
has a third sample (don't use in production!) tomcat-wsp.jks keystore that 
can be used instead.


Demo Web Application
---------------------
The main code lives in the class FederationServlet. This class has been
extended by an implementation of the method doPost().  The doGet 
implementation is the same as in the demo 'simpleWebapp'.

The Web Application contains a service.jsp which provides a button to 
trigger the Web Service call which is in the doPost implementation. CXF
then requests a SAML token from the STS on behalf of the security token
used during the Web Application Login before sending the SOAP request to 
the Web Service.

The FederationServlet prints the string (showing the authenticated browser 
user) returned from the Web Service.


Demo Web Service
---------------------
The main and only code lives in the class GreeterImpl. It reads the 
authenticated principal from the JAX-WS WebServiceContext and returns
the principal name to the Web Service Client (Web Application).

The interesting pieces are in applicationContext.xml and the 
WS-SecurityPolicy definition in the WSDL hello_world.wsdl, no security
related programming is required within the Java code.


Building the demo using Maven
-----------------------------
From the base directory of this sample (i.e., where this README file is
located), the pom.xml file is used to build and run the demo. From a 
command prompt, enter:

mvn clean install   (builds the demo and creates two WAR files for 
Servlet deployment to the Tomcat-RP and Tomcat-WSP instances)


Deploying the demo to Tomcat
----------------------------
You can manually copy each generated WAR file to the appropriate
Tomcat webapps folder, or use the Tomcat Maven Plugin as described 
in the README file in the example folder root.


Test the demo
-------------
Enter the following URL into the browser (TCP port depends on 
your HTTP settings):

1) https://localhost:8443/fedizhelloworld/secure/fedservlet

The browser is redirected to the IDP and prompts for username and
password. As described in the IDP installation, the following 
users are already set up:

User: alice   Password: ecila
User: bob     Password: bob
User: ted     Password: det

2) https://localhost:8443/fedizhelloworld/secure/service.jsp

Click "Call Service"
The authenticated user will be displayed again.


