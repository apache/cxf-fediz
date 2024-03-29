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

package org.apache.cxf.fediz.systests.cxf;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.systests.common.AbstractExpiryTests;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;

/**
 * Some token expiry tests
 */
public class TokenExpiryTest extends AbstractExpiryTests {

    static String idpHttpsPort;
    static String rpHttpsPort;

    private static Tomcat idpServer;
    private static Tomcat rpServer;

    @BeforeAll
    public static void init() throws Exception {
        idpHttpsPort = System.getProperty("idp.https.port");
        Assertions.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assertions.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        initIdp();
        initRp();
    }

    private static void initIdp() throws LifecycleException {
        idpServer = new Tomcat();
        idpServer.setPort(0);
        final Path targetDir = Paths.get("target").toAbsolutePath();
        idpServer.setBaseDir(targetDir.toString());

        idpServer.getHost().setAppBase("tomcat/idp/webapps");
        idpServer.getHost().setAutoDeploy(true);
        idpServer.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(idpHttpsPort));
        httpsConnector.setSecure(true);
        httpsConnector.setScheme("https");
        httpsConnector.setProperty("keyAlias", "mytomidpkey");
        httpsConnector.setProperty("keystorePass", "tompass");
        httpsConnector.setProperty("keystoreFile", "test-classes/server.jks");
        httpsConnector.setProperty("truststorePass", "tompass");
        httpsConnector.setProperty("truststoreFile", "test-classes/server.jks");
        httpsConnector.setProperty("clientAuth", "want");
        // httpsConnector.setProperty("clientAuth", "false");
        httpsConnector.setProperty("sslProtocol", "TLS");
        httpsConnector.setProperty("SSLEnabled", "true");

        idpServer.getService().addConnector(httpsConnector);

        idpServer.addWebapp("/fediz-idp-sts", "fediz-idp-sts");
        idpServer.addWebapp("/fediz-idp", "fediz-idp");

        idpServer.start();
    }

    private static void initRp() throws LifecycleException {
        rpServer = new Tomcat();
        rpServer.setPort(0);
        final Path targetDir = Paths.get("target").toAbsolutePath();
        rpServer.setBaseDir(targetDir.toString());

        rpServer.getHost().setAppBase("tomcat/rp/webapps");
        rpServer.getHost().setAutoDeploy(true);
        rpServer.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(rpHttpsPort));
        httpsConnector.setSecure(true);
        httpsConnector.setScheme("https");
        httpsConnector.setProperty("keyAlias", "mytomidpkey");
        httpsConnector.setProperty("keystorePass", "tompass");
        httpsConnector.setProperty("keystoreFile", "test-classes/server.jks");
        httpsConnector.setProperty("truststorePass", "tompass");
        httpsConnector.setProperty("truststoreFile", "test-classes/server.jks");
        // httpsConnector.setProperty("clientAuth", "false");
        httpsConnector.setProperty("clientAuth", "want");
        httpsConnector.setProperty("sslProtocol", "TLS");
        httpsConnector.setProperty("SSLEnabled", "true");

        rpServer.getService().addConnector(httpsConnector);

        rpServer.addWebapp("/fedizhelloworld", "cxfWebappExpiry");

        rpServer.start();
    }

    @AfterAll
    public static void cleanup() throws Exception {
        try {
            shutdownServer(idpServer);
        } finally {
            shutdownServer(rpServer);
        }
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

    public String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    public String getRpHttpsPort() {
        return rpHttpsPort;
    }

    public String getServletContextName() {
        return "fedizhelloworld";
    }

}
