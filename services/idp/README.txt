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
