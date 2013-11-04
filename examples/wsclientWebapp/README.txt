Web Service Client Web Application Demo
=======================================

This demo builds on the simpleWebapp sample to show a Relying Party (RP) web application
using an IDP-provided SAML token to access a third-party web service.
Here the IDP authenticates the browser user that the web application requested the token on behalf of,
and uses its STS to issue the token which fulfills the web service's security requirements.
From the SAML token the Web Service is informed which browser user triggered the Web Service call.

Running this sample consists of four steps:

- Configure Servlet Container (ex. Tomcat) instance for the IDP
- Configure Servlet Container (ex. Tomcat) instance for the RP
- Configure Servlet Container (ex. Tomcat) instance for Web Service Provider (WSP)
- Build the project
- Deploying the demo WARs to the RP and WSP Servlet Container isntance

Please review the README in the samples main directory before continuing.
You may wish to run the simpleWebapp demo first as this is an extended demo.


Configure the Servlet Container IDP (ex. Tomcat)
------------------------------------------------
Make sure the separate Servlet Container instance hosting the Fediz IDP
and IDP STS has been configured and is running as described here:  
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

Configure the Servlet Container for WSP (Web Service Provider)
--------------------------------------------------------------
To better model a real-world environment the web service provider is hosted
on a third Serlvet Container instance separate from the RP and IDP instances.
You can follow the Tomcat/Jetty configuration instructions given here for the IDP
Tomcat instance: 
http://cxf.apache.org/fediz-idp.html
but
1) different HTTPS ports from the IDP and RP instances.
This sample uses 10080 for HTTP, 10443 for HTTPS, and 10005 as the server communication 
2) don't reuse the IDP SSL keystore, the examples/samplekeys 
folder has a third sample (don't use in production!) wsp-ssl-server.jks keystore
that can be used instead--check the README in the samplekeys folder for 
more information about the keystores used.


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


Demo Web Service Provider
-------------------------
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
Servlet deployment to the Servlet Container RP and WSP instances)


Deploying the demo WARs to Servlet Container RP and WSP (ex. Tomcat)
--------------------------------------------------------------------
First copy this sample's Fediz Configuration file (src/main/config/fediz_config.xml)
into the Tomcat RP's conf folder.  This configuration references the 
Java keystore 'rp-ssl-server.jks' available in Fediz' examples/samplekeys folder 
but should already be in the Tomcat RP's root folder when you configured this
instance as stated in the prerequisites.  (If you did the Fediz simpleWebapp 
sample first you can keep the fediz_config.xml from that sample, as it's 
identical to this sample's.)

Then, either manually copy this sample's generated WAR file to the Tomcat-RP's 
webapps folder, or use the Tomcat Maven Plugin as described in the README file 
in the example folder root.

After deploying the web service provider, make sure you can see its
WSDL at http://localhost:10080/fedizservice/GreeterService?wsdl
to confirm it has successfully loaded.


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


