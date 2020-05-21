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

package org.apache.cxf.fediz.systests.federation.wsfed;


import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import javax.servlet.ServletException;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * This is a test for federation using a WS-Federation enabled web application. The web application is configured
 * to use a different realm to that of the IdP. The IdP then redirects to a third party IdP for authentication.
 * The third party IdPs that are tested are as follows:
 *  - WS-Federation (Fediz)
 *  - SAML SSO (Fediz)
 *  - SAML SSO (custom webapp - supports POST binding as well)
 *  - OIDC (custom webapp)
 */
public class WSFedTest {

    private enum ServerType {
        IDP, REALMB, SAMLSSO, OIDC, RP
    }

    private static final String IDP_HTTPS_PORT = System.getProperty("idp.https.port");
    private static final String IDP_REALMB_HTTPS_PORT = System.getProperty("idp.realmb.https.port");
    private static final String IDP_SAMLSSO_HTTPS_PORT = System.getProperty("idp.samlsso.https.port");
    private static final String IDP_OIDC_HTTPS_PORT = System.getProperty("idp.oidc.https.port");
    private static final String RP_HTTPS_PORT = System.getProperty("rp.https.port");

    private static Tomcat idpServer;
    private static Tomcat idpRealmbServer;
    private static Tomcat idpSamlSSOServer;
    private static Tomcat idpOIDCServer;
    private static Tomcat rpServer;

    @BeforeClass
    public static void init() throws Exception {
        assertNotNull("Property 'idp.https.port' null", IDP_HTTPS_PORT);
        assertNotNull("Property 'idp.realmb.https.port' null", IDP_REALMB_HTTPS_PORT);
        assertNotNull("Property 'idp.samlsso.https.port' null", IDP_SAMLSSO_HTTPS_PORT);
        assertNotNull("Property 'idp.oidc.https.port' null", IDP_OIDC_HTTPS_PORT);
        assertNotNull("Property 'rp.https.port' null", RP_HTTPS_PORT);

        idpServer = startServer(ServerType.IDP, IDP_HTTPS_PORT);
        idpRealmbServer = startServer(ServerType.REALMB, IDP_REALMB_HTTPS_PORT);
        idpSamlSSOServer = startServer(ServerType.SAMLSSO, IDP_SAMLSSO_HTTPS_PORT);
        idpOIDCServer = startServer(ServerType.OIDC, IDP_OIDC_HTTPS_PORT);
        rpServer = startServer(ServerType.RP, RP_HTTPS_PORT);
    }

    private static Tomcat startServer(ServerType serverType, String port)
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
        httpsConnector.setAttribute("keystorePass", "tompass");
        httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("keyAlias", "mytomidpkey");
        httpsConnector.setAttribute("truststorePass", "tompass");
        httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("clientAuth", "want");

        if (serverType == ServerType.IDP) {
            server.getHost().setAppBase("tomcat/idp/webapps");

            Path stsWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.toString());

            Path idpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.toString());
        } else if (serverType == ServerType.REALMB) {
            server.getHost().setAppBase("tomcat/idprealmb/webapps");

            Path stsWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp-sts-realmb");
            server.addWebapp("/fediz-idp-sts-realmb", stsWebapp.toString());

            Path idpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp-realmb");
            server.addWebapp("/fediz-idp-realmb", idpWebapp.toString());
        } else if (serverType == ServerType.SAMLSSO) {
            server.getHost().setAppBase("tomcat/idpsamlsso/webapps");

            Path idpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("idpsaml");
            server.addWebapp("/idp", idpWebapp.toString());
        } else if (serverType == ServerType.OIDC) {
            server.getHost().setAppBase("tomcat/idpoidc/webapps");

            Path idpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("idpoidc");
            server.addWebapp("/idpoidc", idpWebapp.toString());
        } else {
            server.getHost().setAppBase("tomcat/rp/webapps");

            httpsConnector.setAttribute("clientAuth", "false");

            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(targetDir.resolve("test-classes").resolve("fediz_config_wsfed.xml").toString());

            Path rpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("simpleWebapp");

            server.addWebapp("/wsfed", rpWebapp.toString()).getPipeline().addValve(fa);

            server.addWebapp("/samlsso", rpWebapp.toString()).getPipeline().addValve(fa);

            server.addWebapp("/samlssocustom", rpWebapp.toString()).getPipeline().addValve(fa);

            server.addWebapp("/samlssocustompost", rpWebapp.toString()).getPipeline().addValve(fa);

            server.addWebapp("/oidc", rpWebapp.toString()).getPipeline().addValve(fa);
        }

        server.getService().addConnector(httpsConnector);

        server.start();

        return server;
    }

    @AfterClass
    public static void cleanup() {
        shutdownServer(idpServer);
        shutdownServer(idpRealmbServer);
        shutdownServer(idpSamlSSOServer);
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
        return IDP_HTTPS_PORT;
    }

    public String getIdpRealmbHttpsPort() {
        return IDP_REALMB_HTTPS_PORT;
    }

    public String getRpHttpsPort() {
        return RP_HTTPS_PORT;
    }

    public String getServletContextName() {
        return "fedizhelloworld";
    }

    @org.junit.Test
    public void testWSFederation() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/wsfed/secure/fedservlet";
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            login(url, user, password, getIdpRealmbHttpsPort(), IDP_HTTPS_PORT);

        assertTrue("Principal not alice",
                          bodyTextContent.contains("userPrincipal=alice"));
        assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          bodyTextContent.contains(claim + "=Alice"));
        claim = ClaimTypes.LASTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          bodyTextContent.contains(claim + "=Smith"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          bodyTextContent.contains(claim + "=alice@realma.org"));
    }

    @org.junit.Test
    public void testSAMLSSOFedizIdP() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlsso/secure/fedservlet";
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            login(url, user, password, getIdpRealmbHttpsPort(), getIdpHttpsPort(), true);

        assertTrue("Principal not alice",
                          bodyTextContent.contains("userPrincipal=alice"));
        assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          bodyTextContent.contains(claim + "=Alice"));
        claim = ClaimTypes.LASTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          bodyTextContent.contains(claim + "=Smith"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          bodyTextContent.contains(claim + "=alice@realma.org"));
    }

    @org.junit.Test
    public void testSAMLSSOCustom() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlssocustom/secure/fedservlet";
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            login(url, user, password, IDP_SAMLSSO_HTTPS_PORT, IDP_HTTPS_PORT, false);

        assertTrue("Principal not alice",
                          bodyTextContent.contains("userPrincipal=alice"));
        assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          bodyTextContent.contains(claim + "=Alice"));
        claim = ClaimTypes.LASTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          bodyTextContent.contains(claim + "=Smith"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          bodyTextContent.contains(claim + "=alice@realma.org"));
    }

    @org.junit.Test
    public void testSAMLSSOCustomPostBinding() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlssocustompost/secure/fedservlet";
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            login(url, user, password, IDP_SAMLSSO_HTTPS_PORT, IDP_HTTPS_PORT, true);

        assertTrue("Principal not alice",
                          bodyTextContent.contains("userPrincipal=alice"));
        assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          bodyTextContent.contains(claim + "=Alice"));
        claim = ClaimTypes.LASTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          bodyTextContent.contains(claim + "=Smith"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          bodyTextContent.contains(claim + "=alice@realma.org"));
    }

    @org.junit.Test
    public void testOIDC() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/oidc/secure/fedservlet";
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";

        final String bodyTextContent =
            loginOIDC(url, user, password, IDP_OIDC_HTTPS_PORT, IDP_HTTPS_PORT);

        assertTrue("Principal not alice",
                          bodyTextContent.contains("userPrincipal=alice"));
        assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          bodyTextContent.contains(claim + "=Alice"));
        claim = ClaimTypes.LASTNAME.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          bodyTextContent.contains(claim + "=Smith"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          bodyTextContent.contains(claim + "=alice@realma.org"));
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
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // For some reason, redirecting back to the IdP for "realm a" is not working with htmlunit. So extract
        // the parameters manually from the form, and access the IdP for "realm a" with them
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String wresult = null;
        String wa = null;
        String wctx = null;
        String wtrealm = null;
        for (DomElement result : results) {
            String name = result.getAttributeNS(null, "name");
            String value = result.getAttributeNS(null, "value");
            if ("wresult".equals(name)) {
                wresult = value;
            } else if ("wa".equals(name)) {
                wa = value;
            } else if ("wctx".equals(name)) {
                wctx = value;
            } else if ("wtrealm".equals(name)) {
                wtrealm = value;
            }
        }
        assertNotNull(wresult);
        assertNotNull(wa);
        assertNotNull(wctx);
        assertNotNull(wtrealm);
        webClient.close();

        // Invoke on the IdP for "realm a"
        final WebClient webClient2 = new WebClient();
        webClient2.setCookieManager(cookieManager);
        webClient2.getOptions().setUseInsecureSSL(true);

        String url2 = "https://localhost:" + rpIdpPort + "/fediz-idp/federation"
                + "?wctx=" + wctx
                + "&wa=" + wa
                + "&wtrealm=" + URLEncoder.encode(wtrealm, "UTF8")
                + "&wresult=" + URLEncoder.encode(wresult, "UTF8");

        webClient2.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage2 = webClient2.getPage(url2);
        webClient2.getOptions().setJavaScriptEnabled(true);
        assertEquals("IDP SignIn Response Form", idpPage2.getTitleText());

        // Now redirect back to the RP
        final HtmlForm form2 = idpPage2.getFormByName("signinresponseform");

        final HtmlSubmitInput button2 = form2.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button2.click();
        assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        webClient2.close();
        return rpPage.getBody().getTextContent();
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
            assertTrue("SAML IDP Response Form".equals(idpPage.getTitleText())
                                || "IDP SignIn Response Form".equals(idpPage.getTitleText()));
            for (HtmlForm form : idpPage.getForms()) {
                String name = form.getAttributeNS(null, "name");
                if ("signinresponseform".equals(name) || "samlsigninresponseform".equals(name)) {
                    final HtmlSubmitInput button = form.getInputByName("_eventId_submit");
                    idpPage = button.click();
                }
            }
        }

        assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Now redirect back to the RP
        final HtmlForm form = idpPage.getFormByName("signinresponseform");

        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button.click();
        assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        webClient.close();
        return rpPage.getBody().getTextContent();
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

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id",
                oidcForm.getInputByName("client_id").getValueAttribute()),
            new NameValuePair("redirect_uri",
                oidcForm.getInputByName("redirect_uri").getValueAttribute()),
            new NameValuePair("scope",
                oidcForm.getInputByName("scope").getValueAttribute()),
            new NameValuePair("state",
                oidcForm.getInputByName("state").getValueAttribute()),
            new NameValuePair("session_authenticity_token",
                oidcForm.getInputByName("session_authenticity_token").getValueAttribute()),
            new NameValuePair("oauthDecision", "allow")));

        HtmlPage idpPage = webClient.getPage(request);

        assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Now redirect back to the RP
        final HtmlForm form = idpPage.getFormByName("signinresponseform");

        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button.click();
        assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        webClient.close();
        return rpPage.getBody().getTextContent();
    }
}
