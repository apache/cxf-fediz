Deploy WS-Federation plugin in tomcat 7

1) Pre-requisites:
- Tomcat 7.0.x
- JDK 1.6

2) Prepare tomcat
- create a sub-directory  in ${catalina.home}/lib
- update catalina.properties in ${catalina.home}/conf (see last directory added in the comma seperated list)
common.loader=${catalina.base}/lib,${catalina.base}/lib/*.jar,${catalina.home}/lib,${catalina.home}/lib/*.jar,${catalina.home}/lib/fediz/*.jar

3) Deploy Federation plugin

a) Deploy the JAR's built as part of fediz-core and fediz-tomcat:
fediz-core-*.jar
fediz-tomcat-*.jar

b) deploy the following third party libraries (tested with the mentioned version)
- commons-logging-1.1.1.jar
- joda-time-1.6.2.jar
- opensaml-2.4.1.jar
- openws-1.4.1.jar
- slf4j-api-1.6.1.jar
- slf4j-jdk14-1.6.1.jar
- wss4j-1.6.2.jar
- xmlsec-1.4.5.jar
- xmltooling-1.3.1.jar

c) configure the CA certificates:

- Deploy the keystore (configured in above properties) to the configured location
keystore can be found in fediz-idp-sts/src/test/resources/stsstore.jks
(hint: you can ignore that the private key is contained in this keystore which must not be the case for production)


4) Configure Federation plugin
- Update the web application context configuration either in server.xml or in your web META-INF/context.xml:

Ex. in server.xml:

        <Context path="/fedizhelloworld" docBase="fedizhelloworld">
                <Valve className="org.apache.cxf.fediz.tomcat.FederationAuthenticator"
                       issuerURL="https://localhost:9443/fedizidp/"
                       truststoreFile="conf/signature.properties"
                       truststorePassword="stsspass"
                       trustedIssuer="DoubleItSTSIssuer" />
        </Context>
        
        or embed a context.xml in your WAR in META-INF which contains this (see fediz-tomcat-example):
        (tomcat:redeploy doesn't work 
        <Context>
        	<Valve className="org.apache.cxf.fediz.tomcat.FederationAuthenticator"
                       issuerURL="https://localhost:9443/fedizidp/"
                       truststoreFile="conf/signature.properties"
                       truststorePassword="stsspass"
                       trustedIssuer="DoubleItSTSIssuer" />
		</Context>

