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

package org.apache.cxf.fediz.systests.federation.samlsso;


import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;

import javax.servlet.ServletException;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;
import com.gargoylesoftware.htmlunit.xml.XmlPage;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * This is a test for federation using a SAML SSO enabled web application (using CXF interceptors). The web
 * application is configured to use a different realm to that of the IdP. The IdP then redirects to a third party
 * IdP for authentication. The third party IdPs that are tested are as follows:
 *  - WS-Federation (Fediz)
 *  - SAML SSO (Fediz)
 *  - OIDC (custom webapp)
 */
public class SAMLSSOTest {

    private enum ServerType {
        IDP, REALMB, OIDC, RP
    }

    static String idpHttpsPort;
    static String idpRealmbHttpsPort;
    static String idpSamlSSOHttpsPort;
    static String idpOIDCHttpsPort;
    static String rpHttpsPort;

    private static Tomcat idpServer;
    private static Tomcat idpRealmbServer;
    private static Tomcat idpOIDCServer;
    private static Tomcat rpServer;

    @BeforeClass
    public static void init() throws Exception {
        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        idpRealmbHttpsPort = System.getProperty("idp.realmb.https.port");
        Assert.assertNotNull("Property 'idp.realmb.https.port' null", idpRealmbHttpsPort);
        idpSamlSSOHttpsPort = System.getProperty("idp.samlsso.https.port");
        Assert.assertNotNull("Property 'idp.samlsso.https.port' null", idpSamlSSOHttpsPort);
        idpOIDCHttpsPort = System.getProperty("idp.oidc.https.port");
        Assert.assertNotNull("Property 'idp.oidc.https.port' null", idpOIDCHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        idpServer = startServer(ServerType.IDP, idpHttpsPort);
        idpRealmbServer = startServer(ServerType.REALMB, idpRealmbHttpsPort);
        idpOIDCServer = startServer(ServerType.OIDC, idpOIDCHttpsPort);
        rpServer = startServer(ServerType.RP, rpHttpsPort);
    }

    private static Tomcat startServer(ServerType serverType, String port)
        throws ServletException, LifecycleException, IOException {
        Tomcat server = new Tomcat();
        server.setPort(0);
        String currentDir = new File(".").getCanonicalPath();
        String baseDir = currentDir + File.separator + "target";
        server.setBaseDir(baseDir);

        if (serverType == ServerType.IDP) {
            server.getHost().setAppBase("tomcat/idp/webapps");
        } else if (serverType == ServerType.REALMB) {
            server.getHost().setAppBase("tomcat/idprealmb/webapps");
        } else if (serverType == ServerType.OIDC) {
            server.getHost().setAppBase("tomcat/idpoidc/webapps");
        } else {
            server.getHost().setAppBase("tomcat/rp/webapps");
        }
        server.getHost().setAutoDeploy(true);
        server.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(port));
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

        server.getService().addConnector(httpsConnector);

        if (serverType == ServerType.IDP) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.getAbsolutePath());

            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.getAbsolutePath());
        } else if (serverType == ServerType.REALMB) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts-realmb");
            server.addWebapp("/fediz-idp-sts-realmb", stsWebapp.getAbsolutePath());

            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-realmb");
            server.addWebapp("/fediz-idp-realmb", idpWebapp.getAbsolutePath());
        } else if (serverType == ServerType.OIDC) {
            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "idpoidc");
            server.addWebapp("/idpoidc", idpWebapp.getAbsolutePath());
        } else {
            File rpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "samlssoWebapp");
            server.addWebapp("/samlsso", rpWebapp.getAbsolutePath());
        }

        server.start();

        return server;
    }

    @AfterClass
    public static void cleanup() {
        shutdownServer(idpServer);
        shutdownServer(idpRealmbServer);
        shutdownServer(idpOIDCServer);
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

    public String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    public String getIdpRealmbHttpsPort() {
        return idpRealmbHttpsPort;
    }

    public String getRpHttpsPort() {
        return rpHttpsPort;
    }

    public String getServletContextName() {
        return "fedizhelloworld";
    }

    @org.junit.Test
    public void testWSFederation() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlsso/app1/services/25";
        //System.out.println(url);
        //Thread.sleep(60 * 2 * 1000);

        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            login(url, user, password, getIdpRealmbHttpsPort(), getIdpHttpsPort());

        Assert.assertTrue(bodyTextContent.contains("This is the double number response"));

    }

    @org.junit.Test
    public void testSAMLSSOFedizIdP() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlsso/app2/services/25";
        // System.out.println(url);
        // Thread.sleep(60 * 2 * 1000);
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            login(url, user, password, getIdpRealmbHttpsPort(), getIdpHttpsPort(), true);

        Assert.assertTrue(bodyTextContent.contains("This is the double number response"));
    }

    @org.junit.Test
    public void testOIDC() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlsso/app3/services/25";
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            loginOIDC(url, user, password, idpOIDCHttpsPort, idpHttpsPort);

        Assert.assertTrue(bodyTextContent.contains("This is the double number response"));
    }


    private static String login(String url, String user, String password,
                                String idpPort, String rpIdpPort) throws IOException {
        //
        // Access the RP + get redirected to the IdP for "realm a". Then get redirected to the IdP for
        // "realm b".
        //
        final WebClient webClient = new WebClient();
        CookieManager cookieManager = new CookieManager();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(idpPort)),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);

        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Now redirect back to the IdP for Realm A
        HtmlForm form = idpPage.getFormByName("signinresponseform");

        HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        HtmlPage idpPageRealmA = button.click();

        Assert.assertTrue("SAML IDP Response Form".equals(idpPage.getTitleText())
                          || "IDP SignIn Response Form".equals(idpPage.getTitleText()));
        form = idpPageRealmA.getFormByName("samlsigninresponseform");

        // Now redirect back to the SAML SSO web app
        button = form.getInputByName("_eventId_submit");

        XmlPage rpPage = button.click();

        webClient.close();
        return rpPage.asXml();
    }

    private static String login(String url, String user, String password,
                                String idpPort, String rpIdpPort, boolean postBinding) throws IOException {
        //
        // Access the RP + get redirected to the IdP for "realm a". Then get redirected to the IdP for
        // "realm b".
        //
        final WebClient webClient = new WebClient();
        CookieManager cookieManager = new CookieManager();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(idpPort)),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);

        if (postBinding) {
            Assert.assertTrue("SAML IDP Response Form".equals(idpPage.getTitleText())
                                || "IDP SignIn Response Form".equals(idpPage.getTitleText()));
            for (HtmlForm form : idpPage.getForms()) {
                String name = form.getAttributeNS(null, "name");
                if ("signinresponseform".equals(name) || "samlsigninresponseform".equals(name)) {
                    final HtmlSubmitInput button = form.getInputByName("_eventId_submit");
                    idpPage = button.click();
                }
            }
        }

        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Now redirect back to the RP
        final HtmlForm form = idpPage.getFormByName("samlsigninresponseform");

        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        final XmlPage rpPage = button.click();

        webClient.close();
        return rpPage.asXml();
    }

    private static String loginOIDC(String url, String user, String password,
                                    String idpPort, String rpIdpPort) throws IOException {
        //
        // Access the RP + get redirected to the IdP for "realm a". Then get redirected to the IdP for
        // "realm b".
        //
        final WebClient webClient = new WebClient();
        CookieManager cookieManager = new CookieManager();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
                                                          new AuthScope("localhost", Integer.parseInt(idpPort)),
                                                          new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);

        // The decision page is returned as XML for some reason. So parse it and send a form response back.
        HtmlPage oidcIdpConfirmationPage = webClient.getPage(url);
        final HtmlForm oidcForm = oidcIdpConfirmationPage.getForms().get(0);

        WebRequest request = new WebRequest(new URL(oidcForm.getActionAttribute()), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        String clientId = oidcForm.getInputByName("client_id").getValueAttribute();
        request.getRequestParameters().add(new NameValuePair("client_id", clientId));
        String redirectUri = oidcForm.getInputByName("redirect_uri").getValueAttribute();
        request.getRequestParameters().add(new NameValuePair("redirect_uri", redirectUri));
        String scope = oidcForm.getInputByName("scope").getValueAttribute();
        request.getRequestParameters().add(new NameValuePair("scope", scope));
        String state = oidcForm.getInputByName("state").getValueAttribute();
        request.getRequestParameters().add(new NameValuePair("state", state));
        String authToken = oidcForm.getInputByName("session_authenticity_token").getValueAttribute();
        request.getRequestParameters().add(new NameValuePair("session_authenticity_token", authToken));
        request.getRequestParameters().add(new NameValuePair("oauthDecision", "allow"));

        HtmlPage idpPage = webClient.getPage(request);

        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Now redirect back to the RP
        final HtmlForm form = idpPage.getFormByName("samlsigninresponseform");

        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        final XmlPage rpPage = button.click();

        webClient.close();
        return rpPage.asXml();
    }

}
