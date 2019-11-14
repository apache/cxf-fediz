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
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.UnexpectedPage;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.WebResponse;
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
import com.gargoylesoftware.htmlunit.util.WebConnectionWrapper;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.startup.Tomcat;
import org.apache.commons.codec.binary.Base64;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.common.util.Loader;
import org.junit.Assert;

/**
 * Some OIDC tests.
 */
abstract class AbstractOIDCTest {

    private static String storedClientId;
    private static String storedClient2Id;
    private static String storedClientPassword;
    private static String storedClient2Password;

    protected static void shutdownServer(Tomcat server) {
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

    protected abstract String getIdpHttpsPort();

    protected abstract String getRpHttpsPort();

    protected abstract String getServletContextName();

    // Runs as BeforeClass: Login to the OIDC Clients page + create two new clients
    protected static void loginToClientsPage(String rpPort, String idpPort, String servletContext) throws Exception {
        String url = "https://localhost:" + rpPort + "/" + servletContext + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, idpPort);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        HtmlPage registeredClientPage =
            registerNewClient(webClient, url, "new-client", "https://127.0.0.1",
                              "https://cxf.apache.org", "https://localhost:12345");
        String registeredClientPageBody = registeredClientPage.getBody().getTextContent();
        Assert.assertTrue(registeredClientPageBody.contains("Registered Clients"));
        Assert.assertTrue(registeredClientPageBody.contains("new-client"));
        Assert.assertTrue(registeredClientPageBody.contains("https://127.0.0.1"));

        HtmlTable table = registeredClientPage.getHtmlElementById("registered_clients");
        storedClientId = table.getCellAt(1, 1).asText().trim();
        Assert.assertNotNull(storedClientId);

        // Get the password
        registeredClientPage = webClient.getPage(url + "/" + storedClientId);
        table = registeredClientPage.getHtmlElementById("client");
        storedClientPassword = table.getCellAt(1, 2).asText().trim();

        // Try to register another new client
        registeredClientPage =
            registerNewClient(webClient, url, "new-client2", "https://127.0.1.1",
                              "https://ws.apache.org", "https://localhost:12345");
        registeredClientPageBody = registeredClientPage.getBody().getTextContent();
        Assert.assertTrue(registeredClientPageBody.contains("Registered Clients"));
        Assert.assertTrue(registeredClientPageBody.contains("new-client"));
        Assert.assertTrue(registeredClientPageBody.contains("https://127.0.0.1"));
        Assert.assertTrue(registeredClientPageBody.contains("new-client2"));
        Assert.assertTrue(registeredClientPageBody.contains("https://127.0.1.1"));

        table = registeredClientPage.getHtmlElementById("registered_clients");
        storedClient2Id = table.getCellAt(2, 1).asText().trim();
        if (storedClient2Id.equals(storedClientId)) {
            storedClient2Id = table.getCellAt(1, 1).asText().trim();
        }
        Assert.assertNotNull(storedClient2Id);

        // Get the password
        registeredClientPage = webClient.getPage(url + "/" + storedClient2Id);
        table = registeredClientPage.getHtmlElementById("client");
        storedClient2Password = table.getCellAt(1, 2).asText().trim();
        Assert.assertNotNull(storedClient2Password);

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
    protected static void loginToClientsPageAndDeleteClient(String rpPort, String idpPort, 
                                                            String servletContext) throws Exception {
        String url = "https://localhost:" + rpPort + "/" + servletContext + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, idpPort);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Get the client identifier
        HtmlTable table = loginPage.getHtmlElementById("registered_clients");
        String clientId = table.getCellAt(1, 1).asText().trim();
        Assert.assertNotNull(clientId);
        String clientId2 = table.getCellAt(2, 1).asText().trim();
        Assert.assertNotNull(clientId2);

        // Now go to the specific client page
        HtmlPage registeredClientsPage = deleteClient(webClient, url, clientId);

        // Check we have one more registered clients
        table = registeredClientsPage.getHtmlElementById("registered_clients");
        Assert.assertEquals(2, table.getRowCount());

        // Now delete the other client
        registeredClientsPage = deleteClient(webClient, url, clientId2);

        // Check we have no more registered clients
        table = registeredClientsPage.getHtmlElementById("registered_clients");
        Assert.assertEquals(1, table.getRowCount());

        webClient.close();
    }

    private static HtmlPage deleteClient(WebClient webClient, String url, String clientId) throws Exception {
        HtmlPage clientPage = webClient.getPage(url + "/" + clientId);

        final HtmlForm deleteForm = clientPage.getFormByName("deleteForm");
        Assert.assertNotNull(deleteForm);

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
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Get the new client identifier
        HtmlTable table = loginPage.getHtmlElementById("registered_clients");

        // 2 clients
        Assert.assertEquals(table.getRows().size(), 3);

        // Now check the first client
        String clientId = table.getCellAt(1, 1).asText().trim();
        Assert.assertNotNull(clientId);

        // Check the Date
        String date = table.getCellAt(1, 2).asText().trim();
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd MMM yyyy", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        Assert.assertEquals(dateFormat.format(new Date()), date);

        // Check the redirect URI
        String redirectURI = table.getCellAt(1, 3).asText().trim();
        Assert.assertTrue("https://127.0.0.1".equals(redirectURI)
                          || "https://127.0.1.1".equals(redirectURI));

        // Now check the specific client page
        HtmlPage clientPage = webClient.getPage(url + "/" + clientId);
        HtmlTable clientTable = clientPage.getHtmlElementById("client");
        Assert.assertEquals(clientId, clientTable.getCellAt(1, 0).asText().trim());

        webClient.close();
    }

    // Test that "bob" can't see the clients created by "alice"
    @org.junit.Test
    public void testRegisteredClientsAsBob() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "bob";
        String password = "bob";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Get the new client identifier
        HtmlTable table = loginPage.getHtmlElementById("registered_clients");

        // 2 clients
        Assert.assertEquals(table.getRows().size(), 1);

        webClient.close();
    }

    @org.junit.Test
    public void testOIDCLoginForClient1() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClientId;
        url += "&response_type=code";
        url += "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", storedClientId));
        request.getRequestParameters().add(new NameValuePair("grant_type", "authorization_code"));
        request.getRequestParameters().add(new NameValuePair("code", authorizationCode));

        WebClient webClient2 = setupWebClient("", "", getIdpHttpsPort());
        String data = storedClientId + ":" + storedClientPassword;
        String authorizationHeader = "Basic "
            + Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        final UnexpectedPage responsePage = webClient2.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        Assert.assertNotNull(idToken);
        validateIdToken(idToken, storedClientId);

        webClient.close();
        webClient2.close();
    }

    @org.junit.Test
    public void testOIDCLoginForClient2() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClient2Id;
        url += "&response_type=code";
        url += "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", storedClient2Id));
        request.getRequestParameters().add(new NameValuePair("grant_type", "authorization_code"));
        request.getRequestParameters().add(new NameValuePair("code", authorizationCode));

        WebClient webClient2 = setupWebClient("", "", getIdpHttpsPort());
        String data = storedClient2Id + ":" + storedClient2Password;
        String authorizationHeader = "Basic "
            + Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        final UnexpectedPage responsePage = webClient2.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        Assert.assertNotNull(idToken);
        validateIdToken(idToken, storedClient2Id);

        webClient.close();
        webClient2.close();
    }

    @org.junit.Test
    public void testUsingCodeForOtherClient() throws Exception {
        // Get the code for the first client
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClientId;
        url += "&response_type=code";
        url += "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);

        // Now try and get a token for the second client
        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", storedClientId));
        request.getRequestParameters().add(new NameValuePair("grant_type", "authorization_code"));
        request.getRequestParameters().add(new NameValuePair("code", authorizationCode));

        WebClient webClient2 = setupWebClient("", "", getIdpHttpsPort());
        String data = storedClient2Id + ":" + storedClient2Password;
        String authorizationHeader = "Basic "
            + Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        webClient2.getOptions().setJavaScriptEnabled(false);
        try {
            webClient2.getPage(request);
            Assert.fail();
        } catch (FailingHttpStatusCodeException ex) {
            // expected
        }

        webClient2.close();
    }

    @org.junit.Test
    public void testBadClientId() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClientId + 2;
        url += "&response_type=code";
        url += "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());

        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNull(authorizationCode);

        webClient.close();
    }

    @org.junit.Test
    public void testEmptyClientId() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=";
        url += "&response_type=code";
        url += "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());

        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNull(authorizationCode);

        webClient.close();
    }

    @org.junit.Test
    public void testIncorrectRedirectURI() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClientId;
        url += "&response_type=code";
        url += "&scope=openid";
        url += "&redirect_uri=https://127.0.0.5";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());

        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNull(authorizationCode);

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithInvalidRegistrationURI() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        try {
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1//",
                              "https://cxf.apache.org", "https://localhost:12345");
            Assert.assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        } catch (Exception ex) {
            // expected
        }

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithRegistrationURIFragment() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        try {
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1#fragment",
                              "https://cxf.apache.org", "https://localhost:12345");
            Assert.assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        } catch (Exception ex) {
            // expected
        }

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithInvalidAudienceURI() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        try {
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1/",
                              "https://cxf.apache.org//", "https://localhost:12345");
            Assert.assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        } catch (Exception ex) {
            // expected
        }

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithInvalidLogoutURI() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        try {
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1/",
                              "https://cxf.apache.org/", "https://localhost:12345//");
            Assert.assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        } catch (Exception ex) {
            // expected
        }

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithAudienceURIFragment() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Now try to register a new client
        try {
            HtmlPage errorPage = registerNewClient(webClient, url, "asfxyz", "https://127.0.0.1",
                              "https://cxf.apache.org#fragment", "https://localhost:12345");
            Assert.assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        } catch (Exception ex) {
            // expected
        }

        webClient.close();
    }

    @org.junit.Test
    public void testClientCredentialsSTS() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", "alice"));
        request.getRequestParameters().add(new NameValuePair("client_secret", "ecila"));
        request.getRequestParameters().add(new NameValuePair("grant_type", "client_credentials"));

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setJavaScriptEnabled(false);
        final UnexpectedPage responsePage = webClient.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        Assert.assertTrue(response.contains("access_token"));

        webClient.close();
    }

    @org.junit.Test
    public void testCreateClientWithSupportedTLD() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/console/clients";
        String user = "alice";
        String password = "ecila";

        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Register a client with a supported TLD
        HtmlPage registeredClientPage = registerNewClient(webClient, url, "tld1", "https://www.apache.corp",
            "https://cxf.apache.org", "https://localhost:12345");
        String registeredClientPageBody = registeredClientPage.getBody().getTextContent();
        Assert.assertTrue(registeredClientPageBody.contains("Registered Clients"));
        Assert.assertTrue(registeredClientPageBody.contains("tld1"));
        Assert.assertTrue(registeredClientPageBody.contains("https://www.apache.corp"));

        HtmlTable table = registeredClientPage.getHtmlElementById("registered_clients");
        String clientId = table.getCellAt(3, 1).asText().trim();

        // Register a client with an unsupported TLD
        try {
            HtmlPage errorPage = registerNewClient(webClient, url, "tld2", "https://www.apache.corp2",
                                                   "https://cxf.apache.org", "https://localhost:12345");
            Assert.assertTrue(errorPage.asText().contains("Invalid Client Registration"));
        } catch (Exception ex) {
            // expected
        }

        // Delete the first client above
        deleteClient(webClient, url, clientId);


        webClient.close();
    }

    @org.junit.Test
    public void testLogout() throws Exception {
        // 1. Log in
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClientId;
        url += "&response_type=code";
        url += "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);

        // 2. Get another authorization code without username/password. This should work as we are
        // logged on
        webClient.getCredentialsProvider().clear();
        CodeWebConnectionWrapper wrapper = new CodeWebConnectionWrapper(webClient);

        try {
            webClient.getPage(url);
        } catch (Throwable t) {
            // expected
        }

        wrapper.close();
        authorizationCode = wrapper.getCode();
        Assert.assertNotNull(authorizationCode);

        // 3. Log out
        String logoutUrl = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/logout?";
        logoutUrl += "client_id=" + storedClientId;

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(logoutUrl);
        } catch (Exception ex) {
            Assert.assertTrue(ex.getMessage().contains("Connect to localhost:12345"));
        }

        // 4. Get another authorization code without username/password. This should fail as we have
        // logged out
        try {
            loginAndGetAuthorizationCode(url, webClient);
            Assert.fail("Failure expected after logout");
        } catch (Exception ex) {
            Assert.assertTrue(ex.getMessage().contains("401"));
        }

        webClient.close();
    }

    @org.junit.Test
    public void testLogoutViaTokenHint() throws Exception {
        // 1. Log in
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClientId;
        url += "&response_type=code";
        url += "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);
        webClient.getCredentialsProvider().clear();

        // Now use the code to get an IdToken
        WebClient webClient2 = setupWebClient(user, password, getIdpHttpsPort());
        String data = storedClientId + ":" + storedClientPassword;
        String authorizationHeader = "Basic " + Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        String tokenUrl = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(tokenUrl), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", storedClientId));
        request.getRequestParameters().add(new NameValuePair("grant_type", "authorization_code"));
        request.getRequestParameters().add(new NameValuePair("code", authorizationCode));

        webClient2.getOptions().setJavaScriptEnabled(false);
        final UnexpectedPage responsePage = webClient2.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        Assert.assertNotNull(idToken);
        validateIdToken(idToken, storedClientId);

        webClient2.close();

        // 2. Log out using the token hint
        String logoutUrl = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/logout?";
        logoutUrl += "id_token_hint=" + idToken;

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(logoutUrl);
        } catch (Exception ex) {
            Assert.assertTrue(ex.getMessage().contains("Connect to localhost:12345"));
        }

        // 3. Get another authorization code without username/password. This should fail as we have
        // logged out
        try {
            loginAndGetAuthorizationCode(url, webClient);
            Assert.fail("Failure expected after logout");
        } catch (Exception ex) {
            Assert.assertTrue(ex.getMessage().contains("401"));
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
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));

        // Register a new client

        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);
        request.setRequestParameters(new ArrayList<NameValuePair>());

        request.getRequestParameters().add(new NameValuePair("client_name", "bad_client"));
        request.getRequestParameters().add(new NameValuePair("client_type", "confidential"));
        request.getRequestParameters().add(new NameValuePair("client_redirectURI", "https://127.0.0.1"));
        request.getRequestParameters().add(new NameValuePair("client_audience", ""));
        request.getRequestParameters().add(new NameValuePair("client_logoutURI", ""));
        request.getRequestParameters().add(new NameValuePair("client_homeRealm", ""));
        request.getRequestParameters().add(new NameValuePair("client_csrfToken", "12345"));

        HtmlPage registeredClientPage = webClient.getPage(request);
        Assert.assertTrue(registeredClientPage.asXml().contains("Invalid CSRF Token"));

        webClient.close();
    }

    @org.junit.Test
    public void testOIDCLoginForClient1WithRoles() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClientId;
        url += "&response_type=code";
        url += "&scope=openid";
        url += "&claims=roles";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", storedClientId));
        request.getRequestParameters().add(new NameValuePair("grant_type", "authorization_code"));
        request.getRequestParameters().add(new NameValuePair("code", authorizationCode));

        WebClient webClient2 = setupWebClient("", "", getIdpHttpsPort());
        String data = storedClientId + ":" + storedClientPassword;
        String authorizationHeader = "Basic "
            + Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        final UnexpectedPage responsePage = webClient2.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        Assert.assertNotNull(idToken);
        validateIdToken(idToken, storedClientId, "User");

        webClient.close();
        webClient2.close();
    }

    @org.junit.Test
    public void testOIDCLoginForClient1WithRolesScope() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize?";
        url += "client_id=" + storedClientId;
        url += "&response_type=code";
        url += "&scope=openid%20roles";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", storedClientId));
        request.getRequestParameters().add(new NameValuePair("grant_type", "authorization_code"));
        request.getRequestParameters().add(new NameValuePair("code", authorizationCode));

        WebClient webClient2 = setupWebClient("", "", getIdpHttpsPort());
        String data = storedClientId + ":" + storedClientPassword;
        String authorizationHeader = "Basic "
            + Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        final UnexpectedPage responsePage = webClient2.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        Assert.assertNotNull(idToken);
        validateIdToken(idToken, storedClientId, "User");

        webClient.close();
        webClient2.close();
    }

    @org.junit.Test
    public void testAccessTokenRevocation() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", storedClientId));
        request.getRequestParameters().add(new NameValuePair("grant_type", "authorization_code"));
        request.getRequestParameters().add(new NameValuePair("code", authorizationCode));

        WebClient webClient2 = setupWebClient("", "", getIdpHttpsPort());
        String data = storedClientId + ":" + storedClientPassword;
        String authorizationHeader = "Basic "
            + Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        final UnexpectedPage responsePage = webClient2.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        Assert.assertNotNull(idToken);
        validateIdToken(idToken, storedClientId);

        // Get the access token
        String accessToken = parseToken(response, "access_token");
        Assert.assertNotNull(accessToken);

        // Introspect the token and check it's valid
        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/introspect";
        WebRequest introspectionRequest = new WebRequest(new URL(url), HttpMethod.POST);
        introspectionRequest.setRequestParameters(new ArrayList<NameValuePair>());
        introspectionRequest.getRequestParameters().add(new NameValuePair("token", accessToken));

        UnexpectedPage introspectionResponsePage = webClient2.getPage(introspectionRequest);
        String introspectionResponse = introspectionResponsePage.getWebResponse().getContentAsString();

        Assert.assertTrue(introspectionResponse.contains("\"active\":true"));

        // Now revoke the token
        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/revoke";
        WebRequest revocationRequest = new WebRequest(new URL(url), HttpMethod.POST);
        revocationRequest.setRequestParameters(new ArrayList<NameValuePair>());
        revocationRequest.getRequestParameters().add(new NameValuePair("token", accessToken));

        webClient2.getPage(revocationRequest);

        // Now introspect the token again and check it's not valid
        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/introspect";

        introspectionResponsePage = webClient2.getPage(introspectionRequest);
        introspectionResponse = introspectionResponsePage.getWebResponse().getContentAsString();

        Assert.assertTrue(introspectionResponse.contains("\"active\":false"));

        webClient.close();
        webClient2.close();
    }

    @org.junit.Test
    public void testAccessTokenRevocationWrongClient() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/idp/authorize"
            + "?client_id=" + storedClientId
            + "&response_type=code"
            + "&scope=openid";
        String user = "alice";
        String password = "ecila";

        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);

        // Now use the code to get an IdToken

        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/token";
        WebRequest request = new WebRequest(new URL(url), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", storedClientId));
        request.getRequestParameters().add(new NameValuePair("grant_type", "authorization_code"));
        request.getRequestParameters().add(new NameValuePair("code", authorizationCode));

        WebClient webClient2 = setupWebClient("", "", getIdpHttpsPort());
        String data = storedClientId + ":" + storedClientPassword;
        String authorizationHeader = "Basic "
            + Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        webClient2.addRequestHeader("Authorization", authorizationHeader);
        final UnexpectedPage responsePage = webClient2.getPage(request);
        String response = responsePage.getWebResponse().getContentAsString();

        // Check the IdToken
        String idToken = getIdToken(response);
        Assert.assertNotNull(idToken);
        validateIdToken(idToken, storedClientId);

        // Get the access token
        String accessToken = parseToken(response, "access_token");
        Assert.assertNotNull(accessToken);

        // Introspect the token and check it's valid
        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/introspect";
        WebRequest introspectionRequest = new WebRequest(new URL(url), HttpMethod.POST);
        introspectionRequest.setRequestParameters(new ArrayList<NameValuePair>());
        introspectionRequest.getRequestParameters().add(new NameValuePair("token", accessToken));

        UnexpectedPage introspectionResponsePage = webClient2.getPage(introspectionRequest);
        String introspectionResponse = introspectionResponsePage.getWebResponse().getContentAsString();

        Assert.assertTrue(introspectionResponse.contains("\"active\":true"));

        // Now try to revoke the token as the other client
        WebClient webClient3 = setupWebClient("", "", getIdpHttpsPort());
        String data2 = storedClient2Id + ":" + storedClient2Password;
        String authorizationHeader2 = "Basic "
            + Base64.encodeBase64String(data2.getBytes(StandardCharsets.UTF_8));
        webClient3.addRequestHeader("Authorization", authorizationHeader2);
        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/revoke";
        WebRequest revocationRequest = new WebRequest(new URL(url), HttpMethod.POST);
        revocationRequest.setRequestParameters(new ArrayList<NameValuePair>());
        revocationRequest.getRequestParameters().add(new NameValuePair("token", accessToken));

        webClient3.getPage(revocationRequest);
        webClient3.close();

        // Now introspect the token again and check it's still valid
        url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/oauth2/introspect";

        introspectionResponsePage = webClient2.getPage(introspectionRequest);
        introspectionResponse = introspectionResponsePage.getWebResponse().getContentAsString();

        Assert.assertTrue(introspectionResponse.contains("\"active\":true"));

        webClient.close();
        webClient2.close();
    }

    @org.junit.Test
    public void testJWKKeyService() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/jwk/keys";
        String user = "alice";
        String password = "ecila";

        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        final UnexpectedPage responsePage = webClient.getPage(url);
        String response = responsePage.getWebResponse().getContentAsString();
        Assert.assertTrue(response.contains("alice"));
        Assert.assertTrue(response.contains("RSA"));
        Assert.assertTrue(response.contains("\"e\":"));
        Assert.assertFalse(response.contains("\"d\":"));

        webClient.close();
    }

    @org.junit.Test
    public void testJWKKeyService2() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/jwk2/keys";
        String user = "alice";
        String password = "ecila";

        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        final UnexpectedPage responsePage = webClient.getPage(url);
        String response = responsePage.getWebResponse().getContentAsString();
        Assert.assertTrue(response.contains("2011-04-29"));
        Assert.assertTrue(response.contains("RSA"));
        Assert.assertTrue(response.contains("\"e\":"));
        Assert.assertFalse(response.contains("\"d\":"));

        webClient.close();
    }

    private static WebClient setupWebClient(String user, String password, String idpPort) {
        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(idpPort)),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);

        return webClient;
    }

    private static HtmlPage login(String url, WebClient webClient) throws IOException {
        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Test the SAML Version here
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String wresult = null;
        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                wresult = result.getAttributeNS(null, "value");
                break;
            }
        }
        Assert.assertTrue(wresult != null
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
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String wresult = null;
        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                wresult = result.getAttributeNS(null, "value");
                break;
            }
        }
        Assert.assertTrue(wresult != null
            && wresult.contains("urn:oasis:names:tc:SAML:2.0:cm:bearer"));

        final HtmlForm form = idpPage.getFormByName("signinresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        // Bit of a hack here to get the authorization code - necessary as HtmlUnit tries
        // to follow the server redirect to "https://127.0.0.1" - the redirect URI
        CodeWebConnectionWrapper wrapper = new CodeWebConnectionWrapper(webClient);

        try {
            button.click();
        } catch (Throwable t) {
            // expected
        }

        wrapper.close();
        return wrapper.getCode();
    }

    private static String getIdToken(String parentString) {
        return parseToken(parentString, "id_token");
    }

    private static String parseToken(String parentString, String tag) {
        String foundString =
            parentString.substring(parentString.indexOf(tag)
                                   + (tag + "\":\"").length());
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
        Assert.assertEquals("alice", jwt.getClaim("preferred_username"));
        Assert.assertEquals("accounts.fediz.com", jwt.getClaim(JwtConstants.CLAIM_ISSUER));
        Assert.assertEquals(audience, jwt.getClaim(JwtConstants.CLAIM_AUDIENCE));
        Assert.assertNotNull(jwt.getClaim(JwtConstants.CLAIM_EXPIRY));
        Assert.assertNotNull(jwt.getClaim(JwtConstants.CLAIM_ISSUED_AT));

        // Check role
        if (role != null) {
            List<String> roles = jwt.getClaims().getListStringProperty("roles");
            Assert.assertNotNull(roles);
            Assert.assertFalse(roles.isEmpty());
            Assert.assertEquals(role, roles.get(0));
        }

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(Loader.getResource("oidc.jks").openStream(), "password".toCharArray());
        Certificate cert = keystore.getCertificate("alice");
        Assert.assertNotNull(cert);

        Assert.assertTrue(jwtConsumer.verifySignatureWith((X509Certificate)cert,
                                                          SignatureAlgorithm.RS256));
    }

    private static class CodeWebConnectionWrapper extends WebConnectionWrapper {

        private String code;

        CodeWebConnectionWrapper(WebClient webClient) throws IllegalArgumentException {
            super(webClient);
        }

        public WebResponse getResponse(WebRequest request) throws IOException {
            WebResponse response = super.getResponse(request);
            String location = response.getResponseHeaderValue("Location");
            if (location != null && location.contains("code=")) {
                code = getSubstring(location, "code");
            }

            return response;
        }

        public String getCode() {
            return code;
        }

        private String getSubstring(String parentString, String substringName) {
            String foundString =
                parentString.substring(parentString.indexOf(substringName + "=") + (substringName + "=").length());
            int ampersandIndex = foundString.indexOf('&');
            if (ampersandIndex < 1) {
                ampersandIndex = foundString.length();
            }
            return foundString.substring(0, ampersandIndex);
        }
    }
}
