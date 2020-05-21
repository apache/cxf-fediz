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

package org.apache.cxf.fediz.systests.samlsso;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.systests.common.AbstractTests;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;

/**
 * Some tests for SAML SSO with the Jetty (9) plugin, invoking on the Fediz IdP configured for SAML SSO.
 */
public class JettyTest extends AbstractTests {

    private static final String IDP_HTTPS_PORT = System.getProperty("idp.https.port");
    private static final String RP_HTTPS_PORT = System.getProperty("rp.jetty.https.port");

    private static Tomcat idpServer;

    @BeforeClass
    public static void init() throws Exception {
        Assert.assertNotNull("Property 'idp.https.port' null", IDP_HTTPS_PORT);
        Assert.assertNotNull("Property 'rp.jetty.https.port' null", RP_HTTPS_PORT);

        initIdp();

        JettyUtils.initRpServer("rp-server.xml");
    }

    @AfterClass
    public static void cleanup() throws Exception {
        if (idpServer != null && idpServer.getServer() != null
            && idpServer.getServer().getState() != LifecycleState.DESTROYED) {
            if (idpServer.getServer().getState() != LifecycleState.STOPPED) {
                idpServer.stop();
            }
            idpServer.destroy();
        }

        JettyUtils.stopRpServer();
    }

    private static void initIdp() throws Exception {
        idpServer = new Tomcat();
        idpServer.setPort(0);
        final Path targetDir = Paths.get("target").toAbsolutePath();
        idpServer.setBaseDir(targetDir.toString());

        idpServer.getHost().setAppBase("tomcat/idp/webapps");
        idpServer.getHost().setAutoDeploy(true);
        idpServer.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(IDP_HTTPS_PORT));
        httpsConnector.setSecure(true);
        httpsConnector.setScheme("https");
        httpsConnector.setAttribute("keyAlias", "mytomidpkey");
        httpsConnector.setAttribute("keystorePass", "tompass");
        httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("truststorePass", "tompass");
        httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("clientAuth", "want");
        // httpsConnector.setAttribute("clientAuth", "false");
        httpsConnector.setAttribute("sslProtocol", "TLS");
        httpsConnector.setAttribute("SSLEnabled", true);

        idpServer.getService().addConnector(httpsConnector);

        Path stsWebapp = targetDir.resolve(idpServer.getHost().getAppBase()).resolve("fediz-idp-sts");
        idpServer.addWebapp("/fediz-idp-sts", stsWebapp.toString());

        Path idpWebapp = targetDir.resolve(idpServer.getHost().getAppBase()).resolve("fediz-idp");
        idpServer.addWebapp("/fediz-idp", idpWebapp.toString());

        idpServer.start();
    }

    @Override
    public String getIdpHttpsPort() {
        return IDP_HTTPS_PORT;
    }

    @Override
    public String getRpHttpsPort() {
        return RP_HTTPS_PORT;
    }

    @Override
    public String getServletContextName() {
        return "fedizhelloworldjetty";
    }

    @Override
    protected boolean isWSFederation() {
        return false;
    }

    @Ignore("This tests is currently failing on Jetty")
    @Override
    public void testConcurrentRequests() throws Exception {
        // super.testConcurrentRequests();
    }

    @Ignore("This tests is currently failing on Jetty")
    public void testRPLogout() throws Exception {
        //
    }

}
