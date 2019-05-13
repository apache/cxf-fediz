/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.cxf.fediz.systests.tomcat;


import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.ServletException;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;

public class TomcatLauncher {

    private static final String idpHttpsPort = System.getProperty("idp.https.port");
    private static final String rpHttpsPort = System.getProperty("rp.https.port");

    private static Tomcat idpServer;
    private static Tomcat rpServer;

    public static void startServer(String servletContextName) throws Exception {
        assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        idpServer = startServer(idpHttpsPort, null);
        rpServer = startServer(rpHttpsPort, servletContextName);
    }

    private static Tomcat startServer(String port, String servletContextName)
        throws ServletException, LifecycleException, IOException {
        Tomcat server = new Tomcat();
        server.setPort(0);
        Path targetDir = Paths.get("target").toAbsolutePath();
        server.setBaseDir(targetDir.toString());

        server.getHost().setAutoDeploy(true);
        server.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(port));
        httpsConnector.setSecure(true);
        httpsConnector.setScheme("https");
        httpsConnector.setAttribute("sslProtocol", "TLS");
        httpsConnector.setAttribute("SSLEnabled", true);
        httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("keystorePass", "tompass");
        httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("truststorePass", "tompass");
        httpsConnector.setAttribute("clientAuth", "want");
        server.getService().addConnector(httpsConnector);

        if (null == servletContextName) { // IDP
            server.getHost().setAppBase("tomcat/idp/webapps");

            httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
            httpsConnector.setAttribute("truststorePass", "tompass");

            Path stsWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.toString());

            Path idpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.toString());
        } else { // RP
            server.getHost().setAppBase("tomcat/rp/webapps");

            Path rpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("simpleWebapp");
            Context cxt = server.addWebapp(servletContextName, rpWebapp.toString());

            // Substitute the IDP port. Necessary if running the test in eclipse where port filtering doesn't seem
            // to work
            Path fedizConfig = targetDir.resolve("tomcat").resolve("fediz_config.xml");
            try (InputStream is = TomcatLauncher.class.getResourceAsStream("/fediz_config.xml")) {
                byte[] content = new byte[is.available()];
                is.read(content);
                Files.write(fedizConfig, new String(content).replace("${idp.https.port}", idpHttpsPort).getBytes());
            }

            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(fedizConfig.toString());
            cxt.getPipeline().addValve(fa);
        }

        server.start();

        return server;
    }

    public static void shutdownServer() throws Exception {
        shutdownServer(idpServer);
        shutdownServer(rpServer);
    }

    private static void shutdownServer(Tomcat server) throws LifecycleException {
        if (server != null && server.getServer() != null
            && server.getServer().getState() != LifecycleState.DESTROYED) {
            if (server.getServer().getState() != LifecycleState.STOPPED) {
                server.stop();
            }
            server.destroy();
        }
    }

    public static String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    public static String getRpHttpsPort() {
        return rpHttpsPort;
    }

}
