Basic Setup for Building and Running the Demos
==============================================

As described in the installation notes, extract the Apache CXF Fediz
binary distribution archive into an installation directory
under the root drive.  This creates the apache-fediz-x.x.x folder,
which includes all of the product subdirectories.

To build and run the demos, you must install the J2SE Development
Kit (JDK) 6.0 or later.

All of the samples are built using Apache Maven, version 2.2.x or 3.x.
You can build the samples all at once by running 
"mvn clean install" from the samples root folder or by running
the same command within individual sample folders.  For running
each sample, follow the READMEs located in each sample's folder.

"mvn clean install" will generate a WAR file for the servlet-based
examples.  Either the WAR can be manually copied to your servlet
container's war deployment directory (webapps by default with Tomcat)
or the Tomcat Maven Plugin (http://tomcat.apache.org/maven-plugin.html) 
can be used to auto-install the WAR onto Tomcat.  Note if you're using
this plugin with Tomcat 6 instead of Tomcat 7, change the 
tomcat-maven-plugin URLs in the service/pom.xml files to 
"http://localhost:{port}/manager" (instead of ".../manager/text").

To be able to run the Maven "mvn" command from any folder, be
sure to add the MAVEN_HOME/bin directory to your system PATH
variable.

You can import the projects into Eclipse by running 
mvn eclipse:clean eclipse:eclipse then use Eclipse menu item
File | Import... | Existing Project Into Workspace and choosing
the desired projects you wish to import.


