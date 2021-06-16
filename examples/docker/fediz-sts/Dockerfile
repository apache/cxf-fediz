ARG TOMCAT_VERSION

FROM tomcat:$TOMCAT_VERSION-jdk8-openjdk-slim

ARG TOMCAT_HOME=/usr/local/tomcat

# cleanup
RUN rm -rf $TOMCAT_HOME/webapps/*

COPY target/tomcat/ $TOMCAT_HOME/

EXPOSE 9443
