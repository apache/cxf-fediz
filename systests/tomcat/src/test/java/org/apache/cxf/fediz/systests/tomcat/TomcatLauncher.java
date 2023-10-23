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

import static org.junit.jupiter.api.Assertions.assertNotNull;

public abstract class TomcatLauncher {

    private static final String IDP_HTTPS_PORT = System.getProperty("idp.https.port");
    private static final String RP_HTTPS_PORT = System.getProperty("rp.https.port");

    private static Tomcat idpServer;
    private static Tomcat rpServer;

    public static void startServer(String servletContextName) throws Exception {
        assertNotNull("Property 'idp.https.port' null", IDP_HTTPS_PORT);
        assertNotNull("Property 'rp.https.port' null", RP_HTTPS_PORT);

        idpServer = startServer(IDP_HTTPS_PORT, null);
        rpServer = startServer(RP_HTTPS_PORT, servletContextName);
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
        httpsConnector.setProperty("sslProtocol", "TLS");
        httpsConnector.setProperty("SSLEnabled", "true");
        httpsConnector.setProperty("keystoreFile", "test-classes/server.jks");
        httpsConnector.setProperty("keystorePass", "tompass");
        httpsConnector.setProperty("truststoreFile", "test-classes/server.jks");
        httpsConnector.setProperty("truststorePass", "tompass");
        httpsConnector.setProperty("clientAuth", "want");
        server.getService().addConnector(httpsConnector);

        if (null == servletContextName) { // IDP
            server.getHost().setAppBase("tomcat/idp/webapps");

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
                Files.write(fedizConfig, new String(content).replace("${idp.https.port}", IDP_HTTPS_PORT).getBytes());
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
        return IDP_HTTPS_PORT;
    }

    public static String getRpHttpsPort() {
        return RP_HTTPS_PORT;
    }

}
