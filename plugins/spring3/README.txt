Fediz configuration for Spring Security 3
---------------------------------------

The Servlet Container installation doesn't have to be updated before a Web Application can be deployed.

It's recommended to use HTTPS to avoid sending tokens/cookies in clear text on the network.
Please check your Servlet Container documentation how to set it up.

Please check the Spring Security example to get more information how to deploy a web application
using Spring Security 3.

The following wiki page explains how to configure the Fediz Spring plugin in your application:
http://cxf.apache.org/fediz-spring.html

The following wiki page explains the fediz configuration which is Container independent:
http://cxf.apache.org/fediz-configuration.html

Note: The Fediz Spring plugin is packaged with your application.
Thus it's recommended to package it with the application
using Apache Maven.
