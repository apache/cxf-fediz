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
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.tomcat.FederationAuthenticator;
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
    private static final String RP_HTTPS_PORT = System.getProperty("rp.https.port");

    private static final String CALLBACK_CONTEXT_1 = "/callback1";
    private static final String REDIRECT_URL_1 = "https://127.0.0.1:" + RP_HTTPS_PORT + CALLBACK_CONTEXT_1;
    private static final String LOGOUT_CONTEXT_1 = "/logout1";
    private static final String LOGOUT_URL_1 = "https://127.0.0.1:" + RP_HTTPS_PORT + LOGOUT_CONTEXT_1;
    private static final String LOGOUT_MSG = "logout";
    private static final String CALLBACK_CONTEXT_2 = "/callback2";
    private static final String REDIRECT_URL_2 = "https://127.0.0.1:" + RP_HTTPS_PORT + CALLBACK_CONTEXT_2;

    private static Tomcat idpServer;
    private static Tomcat rpServer;

    private static String storedClientId;
    private static String storedClient2Id;
    private static String storedClientPassword;
    private static String storedClient2Password;

    protected static void startServer(String servletContextName, String fedizConfigPath) throws Exception {
        assertNotNull("Property 'idp.https.port' null", IDP_HTTPS_PORT);
        assertNotNull("Property 'rp.https.port' null", RP_HTTPS_PORT);

        idpServer = startServer(IDP_HTTPS_PORT, null, null);
        rpServer = startServer(Integer.parseInt(RP_HTTPS_PORT), servletContextName, fedizConfigPath);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        try (InputStream is = Loader.getResource("/server.jks").openStream()) {
            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, "tompass".toCharArray());
            tmf.init(keyStore);
        }
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, tmf.getTrustManagers(), new java.security.SecureRandom()); 
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

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
            final String callbackName = "callback";
            Tomcat.addServlet(ctx, callbackName, new CallbackServlet());
            ctx.addServletMappingDecoded(CALLBACK_CONTEXT_1, callbackName);
            ctx.addServletMappingDecoded(CALLBACK_CONTEXT_2, callbackName);
            final String logoutName = "logout";
            Tomcat.addServlet(ctx, logoutName, new LogoutServlet());
            ctx.addServletMappingDecoded(LOGOUT_CONTEXT_1, logoutName);
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
        URL url = oidcEndpoint(servletContext, "/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClientIDP(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        HtmlPage registeredClientPage =
            registerNewClient(webClient, url, "new-client", REDIRECT_URL_1,
                              "https://cxf.apache.org", LOGOUT_URL_1);
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

        // Get the password
        registeredClientPage = webClient.getPage(url + "/" + storedClient2Id);
        table = registeredClientPage.getHtmlElementById("client");
        storedClient2Password = table.getCellAt(1, 2).asText().trim();
        assertNotNull(storedClient2Password);

        webClient.close();
    }

    private static HtmlPage registerNewClient(WebClient webClient, URL url,
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
        URL url = oidcEndpoint(servletContext, "/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClientIDP(user, password);
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

    private static HtmlPage deleteClient(WebClient webClient, URL url, String clientId) throws Exception {
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
        final URL url = oidcEndpoint("/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClientIDP(user, password);
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
        final URL url = oidcEndpoint("/console/clients");
        String user = "bob";
        String password = "bob";

        // Login to the client page successfully
        WebClient webClient = setupWebClientIDP(user, password);
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

        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode;
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        }

        // Now use the code to get an IdToken
        final String rawToken = getRawToken(authorizationCode, storedClientId, storedClientPassword);

        // Check the IdToken
        validateIdToken(getIdToken(rawToken), storedClientId);
    }

    @org.junit.Test
    public void testOIDCLoginForClient2() throws Exception {
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClient2Id)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode;
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        }

        // Now use the code to get an IdToken
        final String rawToken = getRawToken(authorizationCode, storedClient2Id, storedClient2Password);

        // Check the IdToken
        validateIdToken(getIdToken(rawToken), storedClient2Id);
    }

    @org.junit.Test
    public void testUsingCodeForOtherClient() throws Exception {
        // Get the code for the first client
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            String authorizationCode = loginAndGetAuthorizationCode(url, webClient);

            // Now try and get a token for the second client
            getRawToken(authorizationCode, storedClient2Id, storedClient2Password);
            fail();
        } catch (FailingHttpStatusCodeException ex) {
            assertEquals(Status.BAD_REQUEST.getStatusCode(), ex.getStatusCode());
        }
    }

    @org.junit.Test
    public void testBadClientId() throws Exception {
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId.substring(1))
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            final String response = loginAndGetAuthorizationCode(url, webClient);
            assertTrue(response.contains("invalid_request"));
        }
    }

    @org.junit.Test
    public void testEmptyClientId() throws Exception {
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", "")
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            final String response = loginAndGetAuthorizationCode(url, webClient);
            assertTrue(response.contains("invalid_request"));
        }
    }

    @org.junit.Test
    public void testIncorrectRedirectURI() throws Exception {
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .queryParam("redirect_uri", "https://127.0.0.5")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            loginAndGetAuthorizationCode(url, webClient);
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getStatusCode());
        }
    }

    @org.junit.Test
    public void testCreateClientWithInvalidRegistrationURI() throws Exception {
        final URL url = oidcEndpoint("/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            HtmlPage loginPage = login(url, webClient);
            final String bodyTextContent = loginPage.getBody().getTextContent();
            assertTrue(bodyTextContent.contains("Registered Clients"));

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1//",
                          "https://cxf.apache.org", "https://localhost:12345");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithRegistrationURIFragment() throws Exception {
        final URL url = oidcEndpoint("/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            HtmlPage loginPage = login(url, webClient);
            final String bodyTextContent = loginPage.getBody().getTextContent();
            assertTrue(bodyTextContent.contains("Registered Clients"));

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1#fragment",
                          "https://cxf.apache.org", "https://localhost:12345");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithInvalidAudienceURI() throws Exception {
        final URL url = oidcEndpoint("/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            HtmlPage loginPage = login(url, webClient);
            final String bodyTextContent = loginPage.getBody().getTextContent();
            assertTrue(bodyTextContent.contains("Registered Clients"));

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1/",
                          "https://cxf.apache.org//", "https://localhost:12345");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithInvalidLogoutURI() throws Exception {
        final URL url = oidcEndpoint("/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            HtmlPage loginPage = login(url, webClient);
            final String bodyTextContent = loginPage.getBody().getTextContent();
            assertTrue(bodyTextContent.contains("Registered Clients"));

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1/",
                          "https://cxf.apache.org/", "https://localhost:12345//");
            assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithAudienceURIFragment() throws Exception {
        final URL url = oidcEndpoint("/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            HtmlPage loginPage = login(url, webClient);
            final String bodyTextContent = loginPage.getBody().getTextContent();
            assertTrue(bodyTextContent.contains("Registered Clients"));

            // Now try to register a new client
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1",
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

        try (WebClient webClient = new WebClient()) {
            webClient.getOptions().setUseInsecureSSL(true);
            webClient.getOptions().setJavaScriptEnabled(false);
            final String response = webClient.getPage(request).getWebResponse().getContentAsString();
            assertTrue(response.contains("access_token"));
        }
    }

    @org.junit.Test
    public void testCreateClientWithSupportedTLD() throws Exception {
        final URL url = oidcEndpoint("/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClientIDP(user, password);
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
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClientIDP(user, password);
        final String authorizationCode1 = loginAndGetAuthorizationCode(url, webClient);

        // 2. Get another authorization code without username/password. This should work as we are logged on
        webClient.getCredentialsProvider().clear();

        final String authorizationCode2 = webClient.getPage(url).getWebResponse().getContentAsString();
        assertNotNull(authorizationCode2);
        assertNotEquals(authorizationCode1, authorizationCode2);

        // 3. Log out
        URL logoutUrl =
            UriBuilder.fromUri("https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/logout")
                .queryParam("client_id", storedClientId)
                .build().toURL();

        final String logoutContent = webClient.getPage(logoutUrl).getWebResponse().getContentAsString();
        assertEquals(LOGOUT_MSG, logoutContent);

        // 4. Get another authorization code without username/password. This should fail as we have logged out
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
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClientIDP(user, password);
        final String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        webClient.getCredentialsProvider().clear();

        // Now use the code to get an IdToken
        final String rawToken = getRawToken(authorizationCode, storedClientId, storedClientPassword);

        // Check the IdToken
        String idToken = getIdToken(rawToken);
        validateIdToken(idToken, storedClientId);

        // 2. Log out using the token hint
        URL logoutUrl =
            UriBuilder.fromUri("https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/logout")
                .queryParam("id_token_hint", idToken)
                //.queryParam("post_logout_redirect_uri", LOGOUT_URL_1)
                .build().toURL();

        final String logoutContent = webClient.getPage(logoutUrl).getWebResponse().getContentAsString();
        assertEquals(LOGOUT_MSG, logoutContent);

        // 3. Get another authorization code without username/password. This should fail as we have logged out
        try {
            loginAndGetAuthorizationCode(url, webClient);
            fail("Failure expected after logout");
        } catch (FailingHttpStatusCodeException ex) {
            assertEquals(Status.UNAUTHORIZED.getStatusCode(), ex.getStatusCode());
        }

        webClient.close();
    }

    @org.junit.Test
    public void testLogoutWrongPostLogoutRedirectUri() throws Exception {
        // 1. Log in
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClientIDP(user, password);
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);

        // Now use the code to get an IdToken
        final String rawToken = getRawToken(authorizationCode, storedClientId, storedClientPassword);

        // Check the IdToken
        String idToken = getIdToken(rawToken);
        validateIdToken(idToken, storedClientId);

        // 2. Log out using the token hint
        URL logoutUrl =
            UriBuilder.fromUri("https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/logout")
                .queryParam("id_token_hint", idToken)
                .queryParam("post_logout_redirect_uri", "https://localhost:12345")
                .build().toURL();

        try {
            webClient.getPage(logoutUrl);
            fail("Failure expected using invalid post_logout_redirect_uri");
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(Status.BAD_REQUEST.getStatusCode(), e.getStatusCode());
        } 
    }

    // Test that the form has the correct CSRF token in it when creating a client
    @org.junit.Test
    public void testCSRFClientRegistration() throws Exception {
        final URL url = oidcEndpoint("/console/clients");
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClientIDP(user, password);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        assertTrue(bodyTextContent.contains("Registered Clients"));

        // Register a new client

        WebRequest request = new WebRequest(url, HttpMethod.POST);
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
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .queryParam("claims", "roles")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode;
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        }

        // Now use the code to get an IdToken
        final String rawToken = getRawToken(authorizationCode, storedClientId, storedClientPassword);

        // Check the IdToken
        validateIdToken(getIdToken(rawToken), storedClientId, "User");
    }

    @org.junit.Test
    public void testOIDCLoginForClient1WithRolesScope() throws Exception {
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid roles")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode;
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        }

        // Now use the code to get an IdToken
        final String rawToken = getRawToken(authorizationCode, storedClientId, storedClientPassword);

        // Check the IdToken
        validateIdToken(getIdToken(rawToken), storedClientId, "User");
    }

    @org.junit.Test
    public void testAccessTokenRevocation() throws Exception {
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode;
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        }

        // Now use the code to get an IdToken
        final String rawToken = getRawToken(authorizationCode, storedClientId, storedClientPassword);

        // Check the IdToken
        validateIdToken(getIdToken(rawToken), storedClientId);

        // Get the access token
        String accessToken = parseToken(rawToken, "access_token");
        assertNotNull(accessToken);

        // Introspect the token and check it's valid
        WebRequest introspectionRequest = new WebRequest(oidcEndpoint("/oauth2/introspect"), HttpMethod.POST);
        introspectionRequest.setRequestParameters(Arrays.asList(
            new NameValuePair("token", accessToken)));

        WebClient webClient2 = setupWebClientRP(storedClientId, storedClientPassword);
        String introspectionResponse = webClient2.getPage(introspectionRequest).getWebResponse().getContentAsString();

        assertTrue(introspectionResponse.contains("\"active\":true"));

        // Now revoke the token
        WebRequest revocationRequest = new WebRequest(oidcEndpoint("/oauth2/revoke"), HttpMethod.POST);
        revocationRequest.setRequestParameters(Arrays.asList(
            new NameValuePair("token", accessToken)));

        webClient2.getPage(revocationRequest);

        // Now introspect the token again and check it's not valid
        introspectionResponse = webClient2.getPage(introspectionRequest).getWebResponse().getContentAsString();

        assertTrue(introspectionResponse.contains("\"active\":false"));

        webClient2.close();
    }

    @org.junit.Test
    public void testAccessTokenRevocationWrongClient() throws Exception {
        final URL url = oidcEndpointBuilder("/idp/authorize")
            .queryParam("client_id", storedClientId)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .build().toURL();
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        final String authorizationCode;
        try (WebClient webClient = setupWebClientIDP(user, password)) {
            authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        }

        // Now use the code to get an IdToken
        final String rawToken = getRawToken(authorizationCode, storedClientId, storedClientPassword);

        // Check the IdToken
        validateIdToken(getIdToken(rawToken), storedClientId);

        // Get the access token
        String accessToken = parseToken(rawToken, "access_token");
        assertNotNull(accessToken);

        // Introspect the token and check it's valid
        WebRequest introspectionRequest = new WebRequest(oidcEndpoint("/oauth2/introspect"), HttpMethod.POST);
        introspectionRequest.setRequestParameters(Arrays.asList(
            new NameValuePair("token", accessToken)));

        WebClient webClient2 = setupWebClientRP(storedClientId, storedClientPassword);
        String introspectionResponse = webClient2.getPage(introspectionRequest).getWebResponse().getContentAsString();

        assertTrue(introspectionResponse.contains("\"active\":true"));

        // Now try to revoke the token as the other client
        try (WebClient webClient3 = setupWebClientRP(storedClient2Id, storedClient2Password)) {
            WebRequest revocationRequest = new WebRequest(oidcEndpoint("/oauth2/revoke"), HttpMethod.POST);
            revocationRequest.setRequestParameters(Arrays.asList(
                new NameValuePair("token", accessToken)));

            webClient3.getPage(revocationRequest);
        }

        // Now introspect the token again and check it's still valid
        introspectionResponse = webClient2.getPage(introspectionRequest).getWebResponse().getContentAsString();

        assertTrue(introspectionResponse.contains("\"active\":true"));

        webClient2.close();
    }

    @org.junit.Test
    public void testJWKKeyService2() throws Exception {
        final String response;
        try (WebClient webClient = setupWebClientRP("", "")) {
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
        return setupWebClient(Integer.parseInt(RP_HTTPS_PORT), user, password);
    }

    private static WebClient setupWebClient(int port, String user, String password) {
        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", port),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);

        return webClient;
    }

    private static <P extends Page> P login(URL url, WebClient webClient) throws IOException {
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
        URL url, WebClient webClient
    ) throws Exception {
        final String authorizationCode = login(url, webClient).getWebResponse().getContentAsString();
        assertNotNull(authorizationCode);
        return authorizationCode;
    }

    private String getRawToken(String authorizationCode, String user, String password) throws IOException {
        try (WebClient webClient = setupWebClientRP(user, password)) {
            WebRequest request = new WebRequest(oidcEndpoint("/oauth2/token"), HttpMethod.POST);

            request.setRequestParameters(Arrays.asList(
                new NameValuePair("client_id", storedClientId),
                new NameValuePair("grant_type", "authorization_code"),
                new NameValuePair("code", authorizationCode)));
    
            return webClient.getPage(request).getWebResponse().getContentAsString();
        }
    }

    private static String getIdToken(String jsonToken) {
        return parseToken(jsonToken, "id_token");
    }

    private static String parseToken(String jsonToken, String tag) {
        String foundString =
            jsonToken.substring(jsonToken.indexOf(tag)
                                   + (tag + "\":\"").length());
        int quoteIndex = foundString.indexOf('"');
        if (quoteIndex < 1) {
            quoteIndex = foundString.length();
        }
        return foundString.substring(0, quoteIndex);
    }

    private void validateIdToken(String idToken, String audience) throws IOException {
        validateIdToken(idToken, audience, null);
    }

    private void validateIdToken(String idToken, String audience, String role) throws IOException {
        assertNotNull(idToken);
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
