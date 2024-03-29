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

package org.apache.cxf.fediz.systests.websphere;

import java.io.File;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Ignore;

public class WebsphereTest extends AbstractTests {

    static String idpHttpsPort;
    static String rpHttpsPort;

    private static Tomcat idpServer;
    private static Tomcat rpServer;

    @BeforeAll
    public static void init() {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.webflow", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security.web",
                           "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf.fediz", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf", "info");

        idpHttpsPort = System.getProperty("idp.https.port");
        Assertions.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assertions.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        initIdp();
    }

    private static void initIdp() {
        try {
            idpServer = new Tomcat();
            idpServer.setPort(0);
            String currentDir = new File(".").getCanonicalPath();
            idpServer.setBaseDir(currentDir + File.separator + "target");

            idpServer.getHost().setAppBase("tomcat/idp/webapps");
            idpServer.getHost().setAutoDeploy(true);
            idpServer.getHost().setDeployOnStartup(true);

            Connector httpsConnector = new Connector();
            httpsConnector.setPort(Integer.parseInt(idpHttpsPort));
            httpsConnector.setSecure(true);
            httpsConnector.setScheme("https");
            // httpsConnector.setProperty("keyAlias", keyAlias);
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @AfterAll
    public static void cleanup() {
        try {
            if (idpServer.getServer() != null && idpServer.getServer().getState() != LifecycleState.DESTROYED) {
                if (idpServer.getServer().getState() != LifecycleState.STOPPED) {
                    idpServer.stop();
                }
                idpServer.destroy();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            if (rpServer.getServer() != null && rpServer.getServer().getState() != LifecycleState.DESTROYED) {
                if (rpServer.getServer().getState() != LifecycleState.STOPPED) {
                    rpServer.stop();
                }
                rpServer.destroy();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Ignored because of missing test environment.
     */
    @Override
    @Ignore
    public void testRPMetadata() throws Exception {

    }

    @Override
    public String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    @Override
    public String getRpHttpsPort() {
        return rpHttpsPort;
    }

    @Override
    public String getServletContextName() {
        return "fedizhelloworld";
    }

}
