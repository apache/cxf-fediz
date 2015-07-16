Fediz Plugin for CXF
--------------------

The Fediz plugin for CXF contains two separate pieces of functionality.
The first is a CallbackHandler that allows the SAML Token of the Web
SSO session to be used by the CXF Web Services Stack, i.e. for delegation.
The second is a full WS-Federation RP plugin based solely on Apache CXF, which
is container independent. 

= Delegation scenario =

Pre-requisite is that Fediz is either enabled on the container level or
by Spring Security. This plugin is an add-on which provides the
security context (SAML token) of the Web SSO session to the underyling
Web Services Stack CXF.

The example 'wsclientWebapp' illustrates the use case where a Fediz protected
web application calls a web services on behalf of the browser user.
This is often called impersonation which requires propagation
of the security context.

Note: The Fediz CXF plugin is packaged with your application.
Thus it's recommended to package it with the application
using Apache Maven.

The following wiki page provides more information about the CXF plugin.
http://cxf.apache.org/fediz-cxf.html
