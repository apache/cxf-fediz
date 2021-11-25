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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.systests.common.AbstractTests;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.common.util.DOM2Writer;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Some tests for SAML SSO with the Tomcat plugin, invoking on the Fediz IdP configured for SAML SSO.
 */
public class TomcatPluginTest extends AbstractTests {

    private static final String IDP_HTTPS_PORT = System.getProperty("idp.https.port");
    private static final String RP_HTTPS_PORT = System.getProperty("rp.https.port");

    private static Tomcat idpServer;
    private static Tomcat rpServer;

    @BeforeClass
    public static void init() throws Exception {
        idpServer = startServer(true, Objects.requireNonNull(IDP_HTTPS_PORT, "Property 'idp.https.port' null"));
        rpServer = startServer(false, Objects.requireNonNull(RP_HTTPS_PORT, "Property 'rp.https.port' null"));
    }

    private static Tomcat startServer(boolean idp, String port) throws LifecycleException, IOException {
        final Tomcat server = new Tomcat();
        server.setPort(0);
        final Path targetDir = Paths.get("target").toAbsolutePath();
        server.setBaseDir(targetDir.toString());

        server.getHost().setAutoDeploy(true);
        server.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(port));
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

        server.getService().addConnector(httpsConnector);

        if (idp) {
            server.getHost().setAppBase("tomcat/idp/webapps");

            Path stsWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.toString());

            Path idpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.toString());
        } else {
            server.getHost().setAppBase("tomcat/rp/webapps");

            Path rpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("simpleWebapp");
            Context ctx = server.addWebapp("/fedizhelloworld", rpWebapp.toString());

            // Substitute the IDP port. Necessary if running the test in eclipse where port filtering doesn't seem
            // to work
            Path fedizConfig = targetDir.resolve("tomcat").resolve("fediz_config.xml");
            try (InputStream is = TomcatPluginTest.class.getResourceAsStream("/fediz_config.xml")) {
                byte[] content = new byte[is.available()];
                is.read(content);
                Files.write(fedizConfig,
                    new String(content).replace("${idp.https.port}", IDP_HTTPS_PORT).getBytes());
            }

            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(fedizConfig.toString());
            ctx.getPipeline().addValve(fa);
        }

        server.start();

        return server;
    }

    @AfterClass
    public static void cleanup() {
        shutdownServer(idpServer);
        shutdownServer(rpServer);
    }

    private static void shutdownServer(Tomcat server) {
        try {
            if (server != null && server.getServer() != null
                && server.getServer().getState() != LifecycleState.DESTROYED) {
                if (server.getServer().getState() != LifecycleState.STOPPED) {
                    server.stop();
                }
                server.destroy();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
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
        return "fedizhelloworld";
    }

    @Override
    protected boolean isWSFederation() {
        return false;
    }

    @org.junit.Test
    @org.junit.Ignore
    public void testBrowser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";

        System.out.println("URL: " + url);
        Thread.sleep(5 * 60 * 1000);
    }

    @Test
    public void testModifiedSignatureValue() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        // Get the initial token
        CookieManager cookieManager = new CookieManager();
        final WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Parse the form to get the token (wresult)
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        for (DomElement result : results) {
            if (getTokenName().equals(result.getAttributeNS(null, "name"))) {
                String value = result.getAttributeNS(null, "value");

                // Decode response
                byte[] deflatedToken = Base64Utility.decode(value);
                InputStream inputStream = new ByteArrayInputStream(deflatedToken);

                Document responseDoc = StaxUtils.read(new InputStreamReader(inputStream, "UTF-8"));

                // Modify SignatureValue
                String signatureNamespace = "http://www.w3.org/2000/09/xmldsig#";
                Node signatureValue =
                    responseDoc.getElementsByTagNameNS(signatureNamespace, "SignatureValue").item(0);
                signatureValue.setTextContent("H" + signatureValue.getTextContent());

                // Re-encode response
                String responseMessage = DOM2Writer.nodeToString(responseDoc);
                result.setAttributeNS(null, "value", Base64Utility.encode(responseMessage.getBytes()));
            }
        }

        // Invoke back on the RP

        final HtmlForm form = idpPage.getFormByName(getLoginFormName());
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        try {
            button.click();
            Assert.fail("Failure expected on a modified signature");
        } catch (FailingHttpStatusCodeException ex) {
            // expected
            Assert.assertTrue(401 == ex.getStatusCode() || 403 == ex.getStatusCode());
        }

        webClient.close();
    }

    @Test
    public void testAliceModifiedContext() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        // Get the initial token
        CookieManager cookieManager = new CookieManager();
        final WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Parse the form to get the token (wresult)
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        for (DomElement result : results) {
            if (getContextName().equals(result.getAttributeNS(null, "name"))) {
                // Now modify the context
                String value = result.getAttributeNS(null, "value");
                value = "H" + value;
                result.setAttributeNS(null, "value", value);
            }
        }

        // Invoke back on the RP

        final HtmlForm form = idpPage.getFormByName(getLoginFormName());
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        try {
            button.click();
            Assert.fail("Failure expected on a modified context");
        } catch (FailingHttpStatusCodeException ex) {
            // Request Timeout expected here, as the context isn't known - the session is presumed to have expired
            Assert.assertTrue(408 == ex.getStatusCode());
        }

        webClient.close();
    }

}
