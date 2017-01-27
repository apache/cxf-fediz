Building and Installating the IDP
=================================

IPD Realm A
-----------

Build the IDP:
mvn clean install -Prealm-a

Deploy the war target/fediz-idp.war to <tomcat-base-dir>/webapps (default https port: 9443)

IPD Realm B
-----------

Build the IDP:
mvn clean install -Prealm-b

Deploy the war target/fediz-idp-remote.war to <tomcat-base-dir>/webapps (default https port: 12443)

Hint: Servlet Context name different for Remote IDP to get different Cookies.
      Cookies are bound to hostname (default: localhost) and path whereas port is not relevant.


IDP WARs deployed in Servlet Container with different HTTPS ports
-----------------------------------------------------------------

1) update src/main/filters/realm-a/env.properties
...
realmA.port=9443
realmB.port=12443
...

2) update src/main/filters/realm-b/env.properties
...
realmA.port=9443
realmB.port=12443
...


Building and launching the IDP embedded
=======================================

You can launch the IDP from Maven to reduce time in setting up an separate Serlvet Container. The Maven Jetty plugin can be used to deploy the idp and optionally the sts component.

The IDP can be started with:

mvn -Pstandalone,realm-a,sts

If you test the REST/JPA layer, you don't have to start the sts as well (profile 'sts').
If you test WS-Federation with the IDP, you must start the sts as well.
The profile 'standalone' means to start jetty embedded. You can launch both profiles in two different shells (but you MUST NOT run 'clean') otherwise you remove the war, db files of the other IDP.

The following properties are supported idp.https.port, idp.http.port

Default port for profile 'realm-a': 9443, 9080
Default port for profile 'realm-b': 12443, 12080

