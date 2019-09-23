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

package org.apache.cxf.fediz.systests.oidc;


import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.ws.rs.core.Response.Status;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.UnexpectedPage;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSelect;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.html.HtmlTable;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.wss4j.common.util.Loader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Some OIDC tests.
 */
abstract class AbstractOIDCTest {

    private static final Integer IDP_HTTPS_PORT = Integer.getInteger("idp.https.port");
    private static final String RP_HTTPS_PORT = System.getProperty("rp.https.port");

    private static final String CALLBACK_CONTEXT_1 = "/callback1";
    private static final String REDIRECT_URL_1 = "https://127.0.0.1:" + RP_HTTPS_PORT + CALLBACK_CONTEXT_1;
    private static final String CALLBACK_CONTEXT_2 = "/callback2";
    private static final String REDIRECT_URL_2 = "https://127.0.0.1:" + RP_HTTPS_PORT + CALLBACK_CONTEXT_2;

    private static Tomcat idpServer;
    private static Tomcat rpServer;

    private static String storedClientId;
    private static String storedClient2Id;
    private static String storedClientPassword;

    protected static void startServer(String servletContextName, String fedizConfigPath) throws Exception {
        assertNotNull("Property 'idp.https.port' null", IDP_HTTPS_PORT);
        assertNotNull("Property 'rp.https.port' null", RP_HTTPS_PORT);

        idpServer = startServer(IDP_HTTPS_PORT, null, null);
        rpServer = startServer(Integer.parseInt(RP_HTTPS_PORT), servletContextName, fedizConfigPath);

        loginToClientsPage(RP_HTTPS_PORT, servletContextName);
    }

    private static Tomcat startServer(int port, String servletContextName, String fedizConfigPath)
            throws ServletException, LifecycleException, IOException {
        Tomcat server = new Tomcat();
        server.setPort(0);
        Path targetDir = Paths.get("target").toAbsolutePath();
        server.setBaseDir(targetDir.toString());

        server.getHost().setAutoDeploy(true);
        server.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(port);
        httpsConnector.setSecure(true);
        httpsConnector.setScheme("https");
        httpsConnector.setAttribute("sslProtocol", "TLS");
        httpsConnector.setAttribute("SSLEnabled", true);
        httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
        httpsConnector.setAttribute("keystorePass", "tompass");

        if (null == servletContextName) { // IDP
            server.getHost().setAppBase("tomcat/idp/webapps");

            httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
            httpsConnector.setAttribute("truststorePass", "tompass");
            httpsConnector.setAttribute("clientAuth", "want");

            Path stsWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.toString());

            Path idpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve("fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.toString());
        } else { // RP
            server.getHost().setAppBase("tomcat/rp/webapps");

            httpsConnector.setAttribute("clientAuth", "false");

            Path rpWebapp = targetDir.resolve(server.getHost().getAppBase()).resolve(servletContextName);
            Context ctx = server.addWebapp(servletContextName, rpWebapp.toString());

            // Substitute the IDP port. Necessary if running the test in eclipse where port filtering doesn't seem
            // to work
            Path fedizConfig = targetDir.resolve("tomcat").resolve(fedizConfigPath);
            try (InputStream is = AbstractOIDCTest.class.getResourceAsStream('/' + fedizConfigPath)) {
                byte[] content = new byte[is.available()];
                is.read(content);
                Files.write(fedizConfig,
                    new String(content).replace("${idp.https.port}", Integer.toString(IDP_HTTPS_PORT)).getBytes());
            }

            if (!fedizConfigPath.contains("spring")) {
                FederationAuthenticator fa = new FederationAuthenticator();
                fa.setConfigFile(fedizConfig.toString());
                ctx.getPipeline().addValve(fa);
            }

            // callback
            ctx = server.addContext("", null);
            final String servletName = "callback";
            Tomcat.addServlet(ctx, servletName, new CallbackServlet());
            ctx.addServletMappingDecoded(CALLBACK_CONTEXT_1, servletName);
            ctx.addServletMappingDecoded(CALLBACK_CONTEXT_2, servletName);
        }

        server.getService().addConnector(httpsConnector);

        server.start();

        return server;
    }

    protected static void shutdownServer(String servletContextName) throws Exception {
        try {
            loginToClientsPageAndDeleteClient(RP_HTTPS_PORT, servletContextName);
        } finally {
            shutdownServer(idpServer);
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

    private String getRpHttpsPort() {
        return RP_HTTPS_PORT;
    }

    protected abstract String getServletContextName();

    // Runs as BeforeClass: Login to the OIDC Clients page + create two new clients
    private static void loginToClientsPage(String rpPort, String servletContext) throws Exception {
        String url = "https://localhost:" + rpPort + "/" + servletContext + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        HtmlPage registeredClientPage =
            registerNewClient(webClient, url, "new-client", REDIRECT_URL_1,
                              "https://cxf.apache.org", "https://localhost:12345");
        String registeredClientPageBody = registeredClientPage.getBody().getTextContent();
        assertTrue(registeredClientPageBody.contains("Registered Clients"));
        assertTrue(registeredClientPageBody.contains("new-client"));
        assertTrue(registeredClientPageBody.contains(REDIRECT_URL_1));

        HtmlTable table = registeredClientPage.getHtmlElementById("registered_clients");
        storedClientId = table.getCellAt(1, 1).asText().trim();
        assertNotNull(storedClientId);

        // Get the password
        registeredClientPage = webClient.getPage(url + "/" + storedClientId);
        table = registeredClientPage.getHtmlElementById("client");
        storedClientPassword = table.getCellAt(1, 2).asText().trim();

        // Try to register another new client
        registeredClientPage =
            registerNewClient(webClient, url, "new-client2", REDIRECT_URL_2,
                              "https://ws.apache.org", "https://localhost:12346");
        registeredClientPageBody = registeredClientPage.getBody().getTextContent();
        assertTrue(registeredClientPageBody.contains("Registered Clients"));
        assertTrue(registeredClientPageBody.contains("new-client"));
        assertTrue(registeredClientPageBody.contains(REDIRECT_URL_1));
        assertTrue(registeredClientPageBody.contains("new-client2"));
        assertTrue(registeredClientPageBody.contains(REDIRECT_URL_2));

        table = registeredClientPage.getHtmlElementById("registered_clients");
        storedClient2Id = table.getCellAt(2, 1).asText().trim();
        if (storedClient2Id.equals(storedClientId)) {
            storedClient2Id = table.getCellAt(1, 1).asText().trim();
        }
        assertNotNull(storedClient2Id);

        webClient.close();
    }

    private static HtmlPage registerNewClient(WebClient webClient, String url,
                                            String clientName, String redirectURI,
                                            String clientAudience,
                                            String logoutURI) throws Exception {
        HtmlPage registerPage = webClient.getPage(url + "/register");

        final HtmlForm form = registerPage.getForms().get(0);

        // Set new client values
        final HtmlTextInput clientNameInput = form.getInputByName("client_name");
        clientNameInput.setValueAttribute(clientName);
        final HtmlSelect clientTypeSelect = form.getSelectByName("client_type");
        clientTypeSelect.setSelectedAttribute("confidential", true);
        final HtmlTextInput redirectURIInput = form.getInputByName("client_redirectURI");
        redirectURIInput.setValueAttribute(redirectURI);
        final HtmlTextInput clientAudienceURIInput = form.getInputByName("client_audience");
        clientAudienceURIInput.setValueAttribute(clientAudience);
        final HtmlTextInput clientLogoutURI = form.getInputByName("client_logoutURI");
        clientLogoutURI.setValueAttribute(logoutURI);

        final HtmlButton button = form.getButtonByName("submit_button");
        return button.click();
    }

    // Runs as AfterClass: Login to the OIDC Clients page + delete the created clients!
    private static void loginToClientsPageAndDeleteClient(String rpPort, String servletContext)
            throws Exception {
        String url = "https://localhost:" + rpPort + "/" + servletContext + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Get the client identifier
        HtmlTable table = loginPage.getHtmlElementById("registered_clients");
        String clientId = table.getCellAt(1, 1).asText().trim();
        assertNotNull(clientId);
        String clientId2 = table.getCellAt(2, 1).asText().trim();
        assertNotNull(clientId2);

        // Now go to the specific client page
        HtmlPage registeredClientsPage = deleteClient(webClient, url, clientId);

        // Check we have one more registered clients
        table = registeredClientsPage.getHtmlElementById("registered_clients");
        assertEquals(2, table.getRowCount());

        // Now delete the other client
        registeredClientsPage = deleteClient(webClient, url, clientId2);

        // Check we have no more registered clients
        table = registeredClientsPage.getHtmlElementById("registered_clients");
        assertEquals(1, table.getRowCount());

        webClient.close();
    }

    private static HtmlPage deleteClient(WebClient webClient, String url, String clientId) throws Exception {
        HtmlPage clientPage = webClient.getPage(url + "/" + clientId);

        final HtmlForm deleteForm = clientPage.getFormByName("deleteForm");
        assertNotNull(deleteForm);

        // Delete the client
        final HtmlButton button = deleteForm.getButtonByName("submit_delete_button");
        return button.click();
    }

    // Test that we managed to create the clients ok
    @org.junit.Test
    public void testCreatedClients() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Get the new client identifier
        HtmlTable table = loginPage.getHtmlElementById("registered_clients");

        // 2 clients
        assertEquals(table.getRows().size(), 3);

        // Now check the first client
        String clientId = table.getCellAt(1, 1).asText().trim();
        assertNotNull(clientId);

        // Check the Date
        String date = table.getCellAt(1, 2).asText().trim();
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd MMM yyyy", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        assertEquals(dateFormat.format(new Date()), date);

        // Check the redirect URI
        String redirectURI = table.getCellAt(1, 3).asText().trim();
        assertTrue(REDIRECT_URL_1.equals(redirectURI)
                          || REDIRECT_URL_2.equals(redirectURI));

        // Now check the specific client page
        HtmlPage clientPage = webClient.getPage(url + "/" + clientId);
        HtmlTable clientTable = clientPage.getHtmlElementById("client");
        assertEquals(clientId, clientTable.getCellAt(1, 0).asText().trim());

        webClient.close();
    }

    // Test that "bob" can't see the clients created by "alice"
    @org.junit.Test
    public void testRegisteredClientsAsBob() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "bob";
        String password = "bob";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Get the new client identifier
        HtmlTable table = loginPage.getHtmlElementById("registered_clients");

        // 2 clients
        assertEquals(table.getRows().size(), 1);

        webClient.close();
    }

    @org.junit.Test
    public void testOIDCLoginForClient1() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password);
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id", storedClientId),
            new NameValuePair("grant_type", "authorization_code"),
            new NameValuePair("code", authorizationCode)));

        webClient.getOptions().setJavaScriptEnabled(false);
        final UnexpectedPage responsePage = webClient.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        assertNotNull(idToken);
        validateIdToken(idToken, storedClientId);

        webClient.close();
    }

    @org.junit.Test
    public void testOIDCLoginForClient2() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClient2Id
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password);
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id", storedClient2Id),
            new NameValuePair("grant_type", "authorization_code"),
            new NameValuePair("code", authorizationCode)));

        webClient.getOptions().setJavaScriptEnabled(false);
        final UnexpectedPage responsePage = webClient.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        assertNotNull(idToken);
        validateIdToken(idToken, storedClient2Id);

        webClient.close();
    }

    @org.junit.Test
    public void testUsingCodeForOtherClient() throws Exception {
        // Get the code for the first client
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password);
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        assertNotNull(authorizationCode);

        // Now try and get a token for the second client
        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id", storedClient2Id),
            new NameValuePair("grant_type", "authorization_code"),
            new NameValuePair("code", authorizationCode)));

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(request);
            fail();
        } catch (FailingHttpStatusCodeException ex) {
            assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getStatusCode());
        }

        webClient.close();
    }

    @org.junit.Test
    public void testBadClientId() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId.substring(1)
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClient(user, password)) {
            final String response = loginAndGetAuthorizationCode(url, webClient);
            assertTrue(response.contains("invalid_request"));
        }
    }

    @org.junit.Test
    public void testEmptyClientId() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id="
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClient(user, password)) {
            final String response = loginAndGetAuthorizationCode(url, webClient);
            assertTrue(response.contains("invalid_request"));
        }
    }

    @org.junit.Test
    public void testIncorrectRedirectURI() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid"
            + "&redirect_uri=https://127.0.0.5";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClient(user, password);) {
            loginAndGetAuthorizationCode(url, webClient);
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getStatusCode());
        }
    }

    @org.junit.Test
    public void testCreateClientWithInvalidRegistrationURI() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1//",
                          "https://cxf.apache.org", "https://localhost:12345");
        assertTrue(errorPage.asText().contains("Invalid Client Registration"));

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithRegistrationURIFragment() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1#fragment",
                          "https://cxf.apache.org", "https://localhost:12345");
        assertTrue(errorPage.asText().contains("Invalid Client Registration"));

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithInvalidAudienceURI() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1/",
                          "https://cxf.apache.org//", "https://localhost:12345");
        assertTrue(errorPage.asText().contains("Invalid Client Registration"));

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithInvalidLogoutURI() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1/",
                          "https://cxf.apache.org/", "https://localhost:12345//");
        assertTrue(errorPage.asText().contains("Invalid Client Registration"));

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithAudienceURIFragment() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1",
                          "https://cxf.apache.org#fragment", "https://localhost:12345");
        assertTrue(errorPage.asText().contains("Invalid Client Registration"));

        webClient.close();
    }

    @org.junit.Test
    public void testClientCredentialsSTS() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id", "alice"),
            new NameValuePair("client_secret", "ecila"),
            new NameValuePair("grant_type", "client_credentials")));

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setJavaScriptEnabled(false);
        final UnexpectedPage responsePage = webClient.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        assertTrue(response.contains("access_token"));

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithSupportedTLD() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Register a client with a supported TLD
        HtmlPage registeredClientPage = registerNewClient(webClient, url, "tld1", "https://www.apache.corp",
            "https://cxf.apache.org", "https://localhost:12345");
        String registeredClientPageBody = registeredClientPage.getBody().getTextContent();
        assertTrue(registeredClientPageBody.contains("Registered Clients"));
        assertTrue(registeredClientPageBody.contains("tld1"));
        assertTrue(registeredClientPageBody.contains("https://www.apache.corp"));

        HtmlTable table = registeredClientPage.getHtmlElementById("registered_clients");
        String clientId = table.getCellAt(3, 1).asText().trim();

        // Register a client with an unsupported TLD
        HtmlPage errorPage = registerNewClient(webClient, url, "tld2", "https://www.apache.corp2",
                                               "https://cxf.apache.org", "https://localhost:12345");
        assertTrue(errorPage.asText().contains("Invalid Client Registration"));

        // Delete the first client above
        deleteClient(webClient, url, clientId);

        webClient.close();
    }

    @org.junit.Test
    public void testLogout() throws Exception {
        // 1. Log in
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password);
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        assertNotNull(authorizationCode);

        // 2. Get another authorization code without username/password. This should work as we are
        // logged on
        webClient.getCredentialsProvider().clear();

        authorizationCode = webClient.getPage(url).getWebResponse().getContentAsString();
        assertNotNull(authorizationCode);

        // 3. Log out
        String logoutUrl = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/logout"
            + "?client_id=" + storedClientId;

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(logoutUrl);
            fail();
        } catch (HttpHostConnectException ex) {
            assertTrue(ex.getMessage().contains("Connect to localhost:12345"));
        }

        // 4. Get another authorization code without username/password. This should fail as we have
        // logged out
        try {
            loginAndGetAuthorizationCode(url, webClient);
            fail("Failure expected after logout");
        } catch (FailingHttpStatusCodeException ex) {
            assertEquals(Status.UNAUTHORIZED.getStatusCode(), ex.getStatusCode());
        }

        webClient.close();
    }

    @org.junit.Test
    public void testLogoutViaTokenHint() throws Exception {
        // 1. Log in
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password);
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        assertNotNull(authorizationCode);
        webClient.getCredentialsProvider().clear();

        // Now use the code to get an IdToken
        WebClient webClient2 = setupWebClient("", "");
        String data = storedClientId + ":" + storedClientPassword;
        String authorizationHeader = "Basic "
            + Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        String tokenUrl = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(tokenUrl), HttpMethod.POST);

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id", storedClientId),
            new NameValuePair("grant_type", "authorization_code"),
            new NameValuePair("code", authorizationCode)));

        final UnexpectedPage responsePage = webClient2.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        assertNotNull(idToken);
        validateIdToken(idToken, storedClientId);

        webClient2.close();

        // 2. Log out using the token hint
        String logoutUrl = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/logout"
            + "?id_token_hint=" + idToken;

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(logoutUrl);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Connect to localhost:12345"));
        }

        // 3. Get another authorization code without username/password. This should fail as we have
        // logged out
        try {
            loginAndGetAuthorizationCode(url, webClient);
            fail("Failure expected after logout");
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("401"));
        }

        webClient.close();
    }

    // Test that the form has the correct CSRF token in it when creating a client
    @org.junit.Test
    public void testCSRFClientRegistration() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Register a new client

        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);
        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_name", "bad_client"),
            new NameValuePair("client_type", "confidential"),
            new NameValuePair("client_redirectURI", "https://127.0.0.1"),
            new NameValuePair("client_audience", ""),
            new NameValuePair("client_logoutURI", ""),
            new NameValuePair("client_homeRealm", ""),
            new NameValuePair("client_csrfToken", "12345")));

        HtmlPage registeredClientPage = webClient.getPage(request);
        assertTrue(registeredClientPage.asXml().contains("Invalid CSRF Token"));

        webClient.close();
    }

    @org.junit.Test
    public void testOIDCLoginForClient1WithRoles() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid"
            + "&claims=roles";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password);
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id", storedClientId),
            new NameValuePair("grant_type", "authorization_code"),
            new NameValuePair("code", authorizationCode)));

        webClient.getOptions().setJavaScriptEnabled(false);
        final UnexpectedPage responsePage = webClient.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        assertNotNull(idToken);
        validateIdToken(idToken, storedClientId, "User");

        webClient.close();
    }

    @org.junit.Test
    public void testOIDCLoginForClient1WithRolesScope() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid%20roles";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password);
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id", storedClientId),
            new NameValuePair("grant_type", "authorization_code"),
            new NameValuePair("code", authorizationCode)));

        webClient.getOptions().setJavaScriptEnabled(false);
        final UnexpectedPage responsePage = webClient.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        assertNotNull(idToken);
        validateIdToken(idToken, storedClientId, "User");

        webClient.close();
    }



    private static WebClient setupWebClient(String user, String password) {
        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", IDP_HTTPS_PORT),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);

        return webClient;
    }

    private static HtmlPage login(String url, WebClient webClient) throws IOException {
        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Test the SAML Version here
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String wresult = null;
        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                wresult = result.getAttributeNS(null, "value");
                break;
            }
        }
        assertTrue(wresult != null
            && wresult.contains("urn:oasis:names:tc:SAML:2.0:cm:bearer"));

        final HtmlForm form = idpPage.getFormByName("signinresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        return button.click();
    }

    private static String loginAndGetAuthorizationCode(
        String url, WebClient webClient
    ) throws Exception {
        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String wresult = null;
        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                wresult = result.getAttributeNS(null, "value");
                break;
            }
        }
        assertTrue(wresult != null
            && wresult.contains("urn:oasis:names:tc:SAML:2.0:cm:bearer"));

        final HtmlForm form = idpPage.getFormByName("signinresponseform");
        Page page = form.getInputByName("_eventId_submit").click();
        return page.getWebResponse().getContentAsString();
    }

    private static String getIdToken(String parentString) {
        String foundString =
            parentString.substring(parentString.indexOf("id_token")
                                   + "id_token\":\"".length());
        int ampersandIndex = foundString.indexOf('"');
        if (ampersandIndex < 1) {
            ampersandIndex = foundString.length();
        }
        return foundString.substring(0, ampersandIndex);
    }

    private void validateIdToken(String idToken, String audience)
        throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        validateIdToken(idToken, audience, null);
    }

    private void validateIdToken(String idToken, String audience, String role)
        throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(idToken);
        JwtToken jwt = jwtConsumer.getJwtToken();

        // Validate claims
        assertEquals("alice", jwt.getClaim("preferred_username"));
        assertEquals("accounts.fediz.com", jwt.getClaim(JwtConstants.CLAIM_ISSUER));
        assertEquals(audience, jwt.getClaim(JwtConstants.CLAIM_AUDIENCE));
        assertNotNull(jwt.getClaim(JwtConstants.CLAIM_EXPIRY));
        assertNotNull(jwt.getClaim(JwtConstants.CLAIM_ISSUED_AT));

        // Check role
        if (role != null) {
            List<String> roles = jwt.getClaims().getListStringProperty("roles");
            assertNotNull(roles);
            assertFalse(roles.isEmpty());
            assertEquals(role, roles.get(0));
        }

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(Loader.getResource("oidc.jks").openStream(), "password".toCharArray());
        Certificate cert = keystore.getCertificate("alice");
        assertNotNull(cert);

        assertTrue(jwtConsumer.verifySignatureWith((X509Certificate)cert,
                                                          SignatureAlgorithm.RS256));
    }

    @SuppressWarnings("serial")
    public static class CallbackServlet extends GenericServlet {
        @Override
        public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
            final String code = req.getParameter("code");
            if (null != code) {
                res.getOutputStream().write(code.getBytes());
            }
        }
    }

}
