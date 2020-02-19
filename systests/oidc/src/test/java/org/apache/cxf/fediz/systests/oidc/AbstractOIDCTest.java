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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.Page;
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
import com.gargoylesoftware.htmlunit.html.HtmlTableRow;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;
import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.common.JoseConstants;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.common.util.Loader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Some OIDC tests.
 */
abstract class AbstractOIDCTest {

    private static final Integer IDP_HTTPS_PORT = Integer.getInteger("idp.https.port");
    private static final Integer RP_HTTPS_PORT = Integer.getInteger("rp.https.port");

    private static final String CALLBACK_CONTEXT = "/callback";
    private static final String REDIRECT_URL = "https://localhost:" + RP_HTTPS_PORT + CALLBACK_CONTEXT;
    private static final String LOGOUT_CONTEXT = "/logout";
    private static final String LOGOUT_URL = "https://localhost:" + RP_HTTPS_PORT + LOGOUT_CONTEXT;
    private static final String LOGOUT_MSG = "logout";

    private static Tomcat idpServer;
    private static Tomcat rpServer;

    private static String confidentialClientId;
    private static String confidentialClientSecret;
    private static String publicClientId;

    protected static void startServer(String servletContextName, String fedizConfigPath) throws Exception {
        assertNotNull("Property 'idp.https.port' null", IDP_HTTPS_PORT);
        assertNotNull("Property 'rp.https.port' null", RP_HTTPS_PORT);

        idpServer = startServer(IDP_HTTPS_PORT, null, null);
        rpServer = startServer(RP_HTTPS_PORT, servletContextName, fedizConfigPath);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        try (InputStream is = Loader.getResource("/server.jks").openStream()) {
            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, "tompass".toCharArray());
            tmf.init(keyStore);
        }
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, tmf.getTrustManagers(), new java.security.SecureRandom()); 
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        loginToClientsPage(servletContextName);
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
            final String callbackName = "callback";
            Tomcat.addServlet(ctx, callbackName, new CallbackServlet());
            ctx.addServletMappingDecoded(CALLBACK_CONTEXT, callbackName);
            final String logoutName = "logout";
            Tomcat.addServlet(ctx, logoutName, new LogoutServlet());
            ctx.addServletMappingDecoded(LOGOUT_CONTEXT, logoutName);
        }

        server.getService().addConnector(httpsConnector);

        server.start();

        return server;
    }

    protected static void shutdownServer(String servletContextName) throws Exception {
        try {
            loginToClientsPageAndDeleteClient(servletContextName);
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

    protected abstract String getServletContextName();

    // Runs as BeforeClass: Login to the OIDC Clients page + create two new clients
    private static void loginToClientsPage(String servletContext) throws IOException {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint(servletContext, "/console/clients");
            HtmlPage registeredClientsPage = login(clientsUrl, webClient);
            String registeredClientsPageBody = registeredClientsPage.getBody().getTextContent();
            assertTrue(registeredClientsPageBody.contains("Registered Clients"));

            // Now try to register a new client
            registeredClientsPage =
                registerNewClient(webClient, clientsUrl, "confidential-client", REDIRECT_URL,
                                  "https://cxf.apache.org", LOGOUT_URL);
            registeredClientsPageBody = registeredClientsPage.getBody().getTextContent();
            assertTrue(registeredClientsPageBody.contains("confidential-client"));
            assertTrue(registeredClientsPageBody.contains(REDIRECT_URL));

            confidentialClientId = getClientIdByName("confidential-client", registeredClientsPage);

            // Get the password
            confidentialClientSecret = getClientSecret(webClient, clientsUrl, confidentialClientId);

            // Register public client
            registeredClientsPage =
                registerNewClient(webClient, clientsUrl, "public-client", REDIRECT_URL,
                                  "https://ws.apache.org", LOGOUT_URL, false);
            registeredClientsPageBody = registeredClientsPage.getBody().getTextContent();
            assertTrue(registeredClientsPageBody.contains("Registered Clients"));
            assertTrue(registeredClientsPageBody.contains("confidential-client"));
            assertTrue(registeredClientsPageBody.contains(REDIRECT_URL));
            assertTrue(registeredClientsPageBody.contains("public-client"));

            publicClientId = getClientIdByName("public-client", registeredClientsPage);
        }
    }

    private static String getClientIdByName(String clientName, HtmlPage registeredClientsPage) {
        final HtmlTable table = registeredClientsPage.getHtmlElementById("registered_clients");
        for (final HtmlTableRow row : table.getRows()) {
            if (clientName.equals(row.getCell(0).asText())) {
                final String clientId = row.getCell(1).asText();
                assertNotNull(clientId);
                return clientId;
            }
        }
        throw new IllegalArgumentException("Client '" + clientName + "' not found");
    }

    private static String getClientSecret(WebClient webClient, URL clientsUrl, String clientId) throws IOException {
        final HtmlPage registeredClientPage = webClient.getPage(clientsUrl + "/" + clientId);
        final HtmlTable table = registeredClientPage.getHtmlElementById("client");
        assertEquals(clientId, table.getCellAt(1, 0).asText());
        return table.getCellAt(1, 2).asText();
    }

    private static HtmlPage registerNewClient(WebClient webClient, URL clientsUrl,
        String clientName, String redirectURI,
        String clientAudience,
        String logoutURI) throws IOException {
        return registerNewClient(webClient, clientsUrl, clientName, redirectURI, clientAudience, logoutURI, true);
    }

    private static HtmlPage registerNewClient(WebClient webClient, URL clientsUrl,
                                            String clientName, String redirectURI,
                                            String clientAudience,
                                            String logoutURI,
                                            boolean confidential) throws IOException {
        HtmlPage registerPage = webClient.getPage(clientsUrl + "/register");

        final HtmlForm form = registerPage.getForms().get(0);

        // Set new client values
        final HtmlTextInput clientNameInput = form.getInputByName("client_name");
        clientNameInput.setValueAttribute(clientName);
        final HtmlSelect clientTypeSelect = form.getSelectByName("client_type");
        clientTypeSelect.setSelectedAttribute(confidential ? "confidential" : "public", true);
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
    private static void loginToClientsPageAndDeleteClient(String servletContext) throws IOException {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint(servletContext, "/console/clients");
            HtmlPage registeredClientsPage = login(clientsUrl, webClient);

            // Get the client identifier
            HtmlTable table = registeredClientsPage.getHtmlElementById("registered_clients");
            String clientId = table.getCellAt(1, 1).asText();
            assertNotNull(clientId);
            String clientId2 = table.getCellAt(2, 1).asText();
            assertNotNull(clientId2);

            // Now go to the specific client page
            registeredClientsPage = deleteClient(webClient, clientsUrl, clientId);

            // Check we have one more registered clients
            table = registeredClientsPage.getHtmlElementById("registered_clients");
            assertEquals(2, table.getRowCount());

            // Now delete the other client
            registeredClientsPage = deleteClient(webClient, clientsUrl, clientId2);

            // Check we have no more registered clients
            table = registeredClientsPage.getHtmlElementById("registered_clients");
            assertEquals(1, table.getRowCount());
        }
    }

    private static HtmlPage deleteClient(WebClient webClient, URL clientsUrl, String clientId) throws IOException {
        HtmlPage clientPage = webClient.getPage(clientsUrl + "/" + clientId);

        final HtmlForm deleteForm = clientPage.getFormByName("deleteForm");
        assertNotNull(deleteForm);

        // Delete the client
        final HtmlButton button = deleteForm.getButtonByName("submit_delete_button");
        return button.click();
    }

    // Test that we managed to create the clients ok
    @org.junit.Test
    public void testCreatedClients() throws Exception {
        final URL url = oidcEndpoint("/console/clients");

        // Login to the client page successfully
        WebClient webClient = setupWebClientIDP("alice", "ecila");
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Get the new client identifier
        HtmlTable table = loginPage.getHtmlElementById("registered_clients");

        // 2 clients
        assertEquals(table.getRows().size(), 3);

        // Now check the first client
        String clientId = table.getCellAt(1, 1).asText();
        assertNotNull(clientId);

        // Check the Date
        String date = table.getCellAt(1, 2).asText().trim(); // <br/>
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd MMM yyyy", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        assertEquals(dateFormat.format(new Date()), date);

        // Check the redirect URI
        String redirectURI = table.getCellAt(1, 3).asText().trim(); // <br/>
        assertTrue(REDIRECT_URL.equals(redirectURI));

        webClient.close();
    }

    // Test that "bob" can't see the clients created by "alice"
    @org.junit.Test
    public void testRegisteredClientsAsBob() throws Exception {
        final URL url = oidcEndpoint("/console/clients");

        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("bob", "bob")) {
            HtmlPage loginPage = login(url, webClient);
            final String bodyTextContent = loginPage.getBody().getTextContent();
            assertTrue(bodyTextContent.contains("Registered Clients"));

            // Get the new client identifier
            HtmlTable table = loginPage.getHtmlElementById("registered_clients");

            // no clients
            assertEquals(table.getRows().size(), 1);
        }
    }

    @org.junit.Test
    public void testOIDCLoginForConfidentialClient() throws IOException {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        testOIDCLogin(authorizationUrl, confidentialClientId, confidentialClientSecret);
    }

    @org.junit.Test
    public void testOIDCLoginForPublicClient() throws IOException {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", publicClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .queryParam("redirect_uri", REDIRECT_URL)
            .build().toURL();
        testOIDCLogin(authorizationUrl, publicClientId, null);
    }

    private void testOIDCLogin(final URL authorizationUrl, String clientId, String clientSecret) throws IOException {
        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode = loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");

        // Now use the code to get an IdToken
        final Map<String, Object> json = getTokenJson(authorizationCode, clientId, clientSecret);

        // Check the IdToken
        validateIdToken(getIdToken(json), clientId);
    }

    @org.junit.Test
    public void testUsingCodeForOtherClient() throws Exception {
        // Get the code for the first client
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode = loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");
        try {
            // Now try and get a token for the second client
            getTokenJson(authorizationCode, publicClientId, null);
            fail();
        } catch (FailingHttpStatusCodeException ex) {
            assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getStatusCode());
        }
    }

    @org.junit.Test
    public void testBadClientId() throws Exception {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId.substring(1))
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        final String response = loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");
        assertTrue(response.contains("invalid_request"));
    }

    @org.junit.Test
    public void testEmptyClientId() throws Exception {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", "")
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        final String response = loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");
        assertTrue(response.contains("invalid_request"));
    }

    @org.junit.Test
    public void testIncorrectRedirectURI() throws Exception {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .queryParam("redirect_uri", "https://127.0.0.5")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        try {
            loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getStatusCode());
        }
    }

    @org.junit.Test
    public void testCreateClientWithInvalidRegistrationURI() throws Exception {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint("/console/clients");
            login(clientsUrl, webClient);

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, clientsUrl, "asfxyz", "https://127.0.0.1//",
                          "https://cxf.apache.org", "https://localhost:12345");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithRegistrationURIFragment() throws Exception {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint("/console/clients");
            login(clientsUrl, webClient);

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, clientsUrl, "asfxyz", "https://127.0.0.1#fragment",
                          "https://cxf.apache.org", "https://localhost:12345");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithInvalidAudienceURI() throws Exception {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint("/console/clients");
            login(clientsUrl, webClient);

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, clientsUrl, "asfxyz", "https://127.0.0.1/",
                          "https://cxf.apache.org//", "https://localhost:12345");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithInvalidLogoutURI() throws Exception {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint("/console/clients");
            login(clientsUrl, webClient);

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, clientsUrl, "asfxyz", "https://127.0.0.1/",
                          "https://cxf.apache.org/", "https://localhost:12345//");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithAudienceURIFragment() throws Exception {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint("/console/clients");
            login(clientsUrl, webClient);

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, clientsUrl, "asfxyz", "https://127.0.0.1",
                          "https://cxf.apache.org#fragment", "https://localhost:12345");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testClientCredentialsSTS() throws Exception {
        final URL url = oidcEndpoint("/oauth2/token");
        WebRequest request = new WebRequest(url, HttpMethod.POST);

        request.setRequestParameters(Arrays.asList(
            new NameValuePair("client_id", "alice"),
            new NameValuePair("client_secret", "ecila"),
            new NameValuePair("grant_type", "client_credentials")));

        try (WebClient webClient = setupWebClient()) {
            final String response = webClient.getPage(request).getWebResponse().getContentAsString();
            assertTrue(response.contains("access_token"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithSupportedTLD() throws Exception {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint("/console/clients");
            login(clientsUrl, webClient);

            // Register a client with a supported TLD
            HtmlPage registeredClientsPage = registerNewClient(webClient, clientsUrl, "tld1", "https://www.apache.corp",
                "https://cxf.apache.org", "https://localhost:12345");
            String registeredClientPageBody = registeredClientsPage.getBody().getTextContent();
            assertTrue(registeredClientPageBody.contains("tld1"));
            assertTrue(registeredClientPageBody.contains("https://www.apache.corp"));

            final String clientId = getClientIdByName("tld1", registeredClientsPage);

            // Register a client with an unsupported TLD
            HtmlPage errorPage = registerNewClient(webClient, clientsUrl, "tld2", "https://www.apache.corp2",
                                                   "https://cxf.apache.org", "https://localhost:12345");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));

            // Delete the first client above
            deleteClient(webClient, clientsUrl, clientId);
        }
    }

    @org.junit.Test
    public void testLogout() throws Exception {
        // 1. Log in
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final String authorizationCode = login(authorizationUrl, webClient).getWebResponse().getContentAsString();

            // 2. Get another authorization code without username/password. This should work as we are logged on
            final String authorizationCode2 = webClient.getPage(authorizationUrl).getWebResponse().getContentAsString();
            assertNotNull(authorizationCode2);
            assertNotEquals(authorizationCode, authorizationCode2);

            // 3. Log out
            final URL logoutUrl = oidcEndpointBuilder("/idp/logout")
                .queryParam("client_id", confidentialClientId)
                .build().toURL();

            final String logoutContent = webClient.getPage(logoutUrl).getWebResponse().getContentAsString();
            assertEquals(LOGOUT_MSG, logoutContent);

            // 4. Get another authorization code without username/password. This should fail as we have logged out
            try {
                webClient.getPage(authorizationUrl);
                fail("Failure expected after logout");
            } catch (FailingHttpStatusCodeException ex) {
                assertEquals(Status.UNAUTHORIZED.getStatusCode(), ex.getStatusCode());
            }
        }
    }

    @org.junit.Test
    public void testLogoutForConfidentialClientViaTokenHint() throws IOException {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        testLogoutViaTokenHint(authorizationUrl, confidentialClientId, confidentialClientSecret);
    }

    @org.junit.Test
    public void testLogoutForPublicClientViaTokenHint() throws IOException {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", publicClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .queryParam("redirect_uri", REDIRECT_URL)
            .build().toURL();
        testLogoutViaTokenHint(authorizationUrl, publicClientId, null);
    }

    private void testLogoutViaTokenHint(final URL authorizationUrl, String clientId, String clientSecret)
        throws IOException {
        // 1. Login to the OIDC authorization endpoint + get the authorization code
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final String authorizationCode = login(authorizationUrl, webClient).getWebResponse().getContentAsString();

            // Now use the code to get an IdToken
            final Map<String, Object> json = getTokenJson(authorizationCode, clientId, clientSecret);

            // Check the IdToken
            final String idToken = getIdToken(json);
            validateIdToken(idToken, clientId);

            // 2. Log out using the token hint
            final URL logoutUrl = oidcEndpointBuilder("/idp/logout")
                .queryParam("id_token_hint", idToken)
                //.queryParam("post_logout_redirect_uri", LOGOUT_URL) // optional
                .build().toURL();

            final String logoutContent = webClient.getPage(logoutUrl).getWebResponse().getContentAsString();
            assertEquals(LOGOUT_MSG, logoutContent);

            // 3. Get another authorization code without username/password. This should fail as we have logged out
            try {
                webClient.getPage(authorizationUrl);
                fail("Failure expected after logout");
            } catch (FailingHttpStatusCodeException ex) {
                assertEquals(Status.UNAUTHORIZED.getStatusCode(), ex.getStatusCode());
            }
        }
    }

    @org.junit.Test
    public void testLogoutWrongPostLogoutRedirectUri() throws Exception {
        // 1. Log in
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final String authorizationCode = login(authorizationUrl, webClient).getWebResponse().getContentAsString();

            // Now use the code to get an IdToken
            final Map<String, Object> json =
                getTokenJson(authorizationCode, confidentialClientId, confidentialClientSecret);

            // Check the IdToken 
            final String idToken = getIdToken(json);
            validateIdToken(idToken, confidentialClientId);

            // 2. Log out using the token hint
            final URL logoutUrl = oidcEndpointBuilder("/idp/logout")
                .queryParam("id_token_hint", idToken)
                .queryParam("post_logout_redirect_uri", LOGOUT_URL + '/')
                .build().toURL();

            try {
                webClient.getPage(logoutUrl);
                fail("Failure expected using invalid post_logout_redirect_uri");
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getStatusCode());
            }
        }
    }

    // Test that the form has the correct CSRF token in it when creating a client
    @org.junit.Test
    public void testCSRFClientRegistration() throws Exception {
        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint("/console/clients");
            login(clientsUrl, webClient);

            // Register a new client

            WebRequest request = new WebRequest(clientsUrl, HttpMethod.POST);
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
        }
    }

    @org.junit.Test
    public void testOIDCLoginForConfidentialClientWithRoles() throws Exception {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .queryParam("claims", "roles")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode = loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");

        // Now use the code to get an IdToken
        final Map<String, Object> json =
            getTokenJson(authorizationCode, confidentialClientId, confidentialClientSecret);

        // Check the IdToken
        validateIdToken(getIdToken(json), confidentialClientId, "User");
    }

    @org.junit.Test
    public void testOIDCLoginForConfidentialClientWithRolesScope() throws Exception {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid roles")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode = loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");

        // Now use the code to get an IdToken
        final Map<String, Object> json =
            getTokenJson(authorizationCode, confidentialClientId, confidentialClientSecret);

        // Check the IdToken
        validateIdToken(getIdToken(json), confidentialClientId, "User");
    }

    @org.junit.Test
    public void testAccessTokenRevocation() throws Exception {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode = loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");

        // Now use the code to get an IdToken
        final Map<String, Object> json =
            getTokenJson(authorizationCode, confidentialClientId, confidentialClientSecret);

        // Check the IdToken
        validateIdToken(getIdToken(json), confidentialClientId);

        // Get the access token
        String accessToken = json.get("access_token").toString();

        // Introspect the token and check it's valid
        WebRequest introspectionRequest = new WebRequest(oidcEndpoint("/oauth2/introspect"), HttpMethod.POST);
        introspectionRequest.setRequestParameters(Arrays.asList(
            new NameValuePair("token", accessToken)));

        try (WebClient webClient = setupWebClientRP(confidentialClientId, confidentialClientSecret)) {
            String introspectionResponse =
                webClient.getPage(introspectionRequest).getWebResponse().getContentAsString();

            assertTrue(introspectionResponse.contains("\"active\":true"));

            // Now revoke the token
            WebRequest revocationRequest = new WebRequest(oidcEndpoint("/oauth2/revoke"), HttpMethod.POST);
            revocationRequest.setRequestParameters(Arrays.asList(
                new NameValuePair("token", accessToken)));

            webClient.getPage(revocationRequest);

            // Now introspect the token again and check it's not valid
            introspectionResponse = webClient.getPage(introspectionRequest).getWebResponse().getContentAsString();

            assertTrue(introspectionResponse.contains("\"active\":false"));
        }
    }

    @org.junit.Test
    public void testAccessTokenRevocationWrongClient() throws Exception {
        final URL authorizationUrl = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", confidentialClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode = loginAndGetAuthorizationCode(authorizationUrl, "alice", "ecila");

        // Now use the code to get an IdToken
        final Map<String, Object> json =
            getTokenJson(authorizationCode, confidentialClientId, confidentialClientSecret);

        // Check the IdToken
        validateIdToken(getIdToken(json), confidentialClientId);

        // Get the access token
        String accessToken = json.get("access_token").toString();

        // Introspect the token and check it's valid
        WebRequest introspectionRequest = new WebRequest(oidcEndpoint("/oauth2/introspect"), HttpMethod.POST);
        introspectionRequest.setRequestParameters(Arrays.asList(
            new NameValuePair("token", accessToken)));

        WebClient webClient2 = setupWebClientRP(confidentialClientId, confidentialClientSecret);
        String introspectionResponse = webClient2.getPage(introspectionRequest).getWebResponse().getContentAsString();

        assertTrue(introspectionResponse.contains("\"active\":true"));

        try (WebClient webClient = setupWebClientIDP("alice", "ecila")) {
            final URL clientsUrl = oidcEndpoint("/console/clients");
            login(clientsUrl, webClient);

            HtmlPage registeredClientsPage = registerNewClient(webClient, clientsUrl, "client3",
                "https://localhost:12345", "https://cxf.apache.org", "https://localhost:12345");

            final String clientId = getClientIdByName("client3", registeredClientsPage);
            final String clientSecret = getClientSecret(webClient, clientsUrl, clientId);

            // Now try to revoke the token as the other client
            try (WebClient webClient3 = setupWebClientRP(clientId, clientSecret)) {
                WebRequest revocationRequest = new WebRequest(oidcEndpoint("/oauth2/revoke"), HttpMethod.POST);
                revocationRequest.setRequestParameters(Arrays.asList(
                    new NameValuePair("token", accessToken)));

                webClient3.getPage(revocationRequest);
            } finally {
                deleteClient(webClient, clientsUrl, clientId);
            }
        }

        // Now introspect the token again and check it's still valid
        introspectionResponse = webClient2.getPage(introspectionRequest).getWebResponse().getContentAsString();

        assertTrue(introspectionResponse.contains("\"active\":true"));

        webClient2.close();
    }

    @org.junit.Test
    public void testJWKKeyService2() throws Exception {
        final String response;
        try (WebClient webClient = setupWebClient()) {
            response = webClient.getPage(oidcEndpoint("/jwk2/keys")).getWebResponse().getContentAsString();
        }
        assertTrue(response.contains("2011-04-29"));
        assertTrue(response.contains("RSA"));
        assertTrue(response.contains("\"e\":"));
        assertFalse(response.contains("\"d\":"));
    }

    private URL oidcEndpoint(String path) throws IOException {
        return oidcEndpoint(getServletContextName(), path);
    }

    private UriBuilder oidcEndpointBuilder(String path) throws IOException {
        return oidcEndpointBuilder(getServletContextName(), path);
    }

    private static URL oidcEndpoint(String servletContext, String path) throws IOException {
        return oidcEndpointBuilder(servletContext, path)
            .build().toURL();
    }

    private static UriBuilder oidcEndpointBuilder(String servletContext, String path) throws IOException {
        return UriBuilder.fromUri("https://localhost:" + RP_HTTPS_PORT + '/' + servletContext)
            .path(path);
    }

    private static WebClient setupWebClientIDP(String user, String password) {
        return setupWebClient(IDP_HTTPS_PORT, user, password);
    }

    private static WebClient setupWebClientRP(String user, String password) {
        return setupWebClient(RP_HTTPS_PORT, user, password);
    }

    private static WebClient setupWebClient() {
        return setupWebClient(-1, null, null);
    }

    private static WebClient setupWebClient(int port, String user, String password) {
        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        if (-1 != port && null != password) {
            webClient.getCredentialsProvider().setCredentials(
                new AuthScope("localhost", port),
                new UsernamePasswordCredentials(user, password));
        }
        webClient.getOptions().setJavaScriptEnabled(false);
        return webClient;
    }

    private static <P extends Page> P login(URL url, WebClient webClient) throws IOException {
        final HtmlPage idpPage = webClient.getPage(url);
        assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        webClient.getCredentialsProvider().clear();

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

    private static String loginAndGetAuthorizationCode(URL authorizationUrl, String user, String password)
        throws IOException {
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            final String authorizationCode = login(authorizationUrl, webClient).getWebResponse().getContentAsString();
            assertNotNull(authorizationCode);
            return authorizationCode;
        }
    }

    private Map<String, Object> getTokenJson(String authorizationCode, String clientId, String clientSecret)
        throws IOException {
        try (WebClient webClient = setupWebClientRP(clientId, clientSecret)) {
            WebRequest request = new WebRequest(oidcEndpoint("/oauth2/token"), HttpMethod.POST);

            request.setRequestParameters(Arrays.asList(
                new NameValuePair("client_id", clientId),
                new NameValuePair("grant_type", "authorization_code"),
                new NameValuePair("code", authorizationCode)));

            return new JsonMapObjectReaderWriter().fromJson(
                webClient.getPage(request).getWebResponse().getContentAsString());
        }
    }

    private static String getIdToken(Map<String, Object> json) {
        return json.get("id_token").toString();
    }

    private void validateIdToken(String idToken, String audience) throws IOException {
        validateIdToken(idToken, audience, null);
    }

    private void validateIdToken(String idToken, String audience, String role) throws IOException {
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
            assertTrue(roles.contains(role));
        }

        // TODO: jwt.getJwsHeader(JoseConstants.HEADER_KEY_ID))
        assertTrue(jwtConsumer.verifySignatureWith(jsonWebKeys().getKeys().get(0),
            SignatureAlgorithm.valueOf(jwt.getJwsHeader(JoseConstants.HEADER_ALGORITHM).toString())));
    }

    private JsonWebKeys jsonWebKeys() throws IOException {
        return JwkUtils.readJwkSet(oidcEndpointBuilder("/jwk/keys").build());
    }

    @SuppressWarnings("serial")
    public static class CallbackServlet extends GenericServlet {
        @Override
        public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
            final String code = req.getParameter("code");
            if (null != code) {
                res.getWriter().write(code);
            }
        }
    }

    @SuppressWarnings("serial")
    public static class LogoutServlet extends GenericServlet {
        public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
            res.getWriter().write(LOGOUT_MSG);
        }
    }
}
