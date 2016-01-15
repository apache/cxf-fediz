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


import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.html.HtmlTable;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.gargoylesoftware.htmlunit.util.WebConnectionWrapper;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.tomcat7.FederationAuthenticator;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * Some OIDC tests.
 */
public class OIDCTest {

    static String idpHttpsPort;
    static String rpHttpsPort;
    
    private static Tomcat idpServer;
    private static Tomcat rpServer;
    
    @BeforeClass
    public static void init() throws Exception {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.webflow", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security.web", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf.fediz", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf", "info");  
        
        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        initIdp();
        initOidc();
        
        loginToClientsPage(rpHttpsPort, idpHttpsPort);
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
            //httpsConnector.setAttribute("keyAlias", keyAlias);
            httpsConnector.setAttribute("keystorePass", "tompass");
            httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
            httpsConnector.setAttribute("truststorePass", "tompass");
            httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
            httpsConnector.setAttribute("clientAuth", "want");
            // httpsConnector.setAttribute("clientAuth", "false");
            httpsConnector.setAttribute("sslProtocol", "TLS");
            httpsConnector.setAttribute("SSLEnabled", true);

            idpServer.getService().addConnector(httpsConnector);
            
            idpServer.addWebapp("/fediz-idp-sts", "fediz-idp-sts");
            idpServer.addWebapp("/fediz-idp", "fediz-idp");
            
            idpServer.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void initOidc() {
        try {
            rpServer = new Tomcat();
            rpServer.setPort(0);
            String currentDir = new File(".").getCanonicalPath();
            rpServer.setBaseDir(currentDir + File.separator + "target");
            
            rpServer.getHost().setAppBase("tomcat/rp/webapps");
            rpServer.getHost().setAutoDeploy(true);
            rpServer.getHost().setDeployOnStartup(true);
            
            Connector httpsConnector = new Connector();
            httpsConnector.setPort(Integer.parseInt(rpHttpsPort));
            httpsConnector.setSecure(true);
            httpsConnector.setScheme("https");
            //httpsConnector.setAttribute("keyAlias", keyAlias);
            httpsConnector.setAttribute("keystorePass", "tompass");
            httpsConnector.setAttribute("keystoreFile", "test-classes/server.jks");
            httpsConnector.setAttribute("truststorePass", "tompass");
            httpsConnector.setAttribute("truststoreFile", "test-classes/server.jks");
            // httpsConnector.setAttribute("clientAuth", "false");
            httpsConnector.setAttribute("clientAuth", "want");
            httpsConnector.setAttribute("sslProtocol", "TLS");
            httpsConnector.setAttribute("SSLEnabled", true);

            rpServer.getService().addConnector(httpsConnector);
            
            //Context ctx =
            Context cxt = rpServer.addWebapp("/fediz-oidc", "fediz-oidc");
            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(currentDir + File.separator + "target" + File.separator
                             + "test-classes" + File.separator + "fediz_config.xml");
            cxt.getPipeline().addValve(fa);
            
            rpServer.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @AfterClass
    public static void cleanup() throws Exception {
        try {
            loginToClientsPageAndDeleteClient(rpHttpsPort, idpHttpsPort);
        } finally {
            shutdownServers();
        }
    }
    
    private static void shutdownServers() {
        try {
            if (idpServer.getServer() != null
                && idpServer.getServer().getState() != LifecycleState.DESTROYED) {
                if (idpServer.getServer().getState() != LifecycleState.STOPPED) {
                    idpServer.stop();
                }
                idpServer.destroy();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            if (rpServer.getServer() != null
                && rpServer.getServer().getState() != LifecycleState.DESTROYED) {
                if (rpServer.getServer().getState() != LifecycleState.STOPPED) {
                    rpServer.stop();
                }
                rpServer.destroy();
            }
        } catch (Exception e) {
            e.printStackTrace();
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
    
    // Runs as BeforeClass: Login to the OIDC Clients page + create two new clients
    private static void loginToClientsPage(String rpPort, String idpPort) throws Exception {
        String url = "https://localhost:" + rpPort + "/fediz-oidc/clients";
        String user = "alice";
        String password = "ecila";
        
        // Login to the client page successfully
        WebClient webClient = setupWebClient(user, password, idpPort);
        HtmlPage loginPage = login(url, webClient);
        final String bodyTextContent = loginPage.getBody().getTextContent();
        Assert.assertTrue(bodyTextContent.contains("Registered Clients"));
        
        // Now try to register a new client
        String registeredClientPage = 
            registerNewClient(webClient, url, "new-client", "http://127.0.0.1");
        Assert.assertTrue(registeredClientPage.contains("Registered Clients"));
        Assert.assertTrue(registeredClientPage.contains("new-client"));
        Assert.assertTrue(registeredClientPage.contains("http://127.0.0.1"));
        
        // Try to register another new client
        registeredClientPage = 
            registerNewClient(webClient, url, "new-client2", "http://127.0.1.1");
        Assert.assertTrue(registeredClientPage.contains("Registered Clients"));
        Assert.assertTrue(registeredClientPage.contains("new-client"));
        Assert.assertTrue(registeredClientPage.contains("http://127.0.0.1"));
        Assert.assertTrue(registeredClientPage.contains("new-client2"));
        Assert.assertTrue(registeredClientPage.contains("http://127.0.1.1"));
        
        webClient.close();
    }
    
    private static String registerNewClient(WebClient webClient, String url,
                                            String clientName, String redirectURI) throws Exception {
        HtmlPage registerPage = webClient.getPage(url + "/register");
        
        final HtmlForm form = registerPage.getForms().get(0);
        
        // Set new client values
        final HtmlTextInput clientNameInput = form.getInputByName("client_name");
        clientNameInput.setValueAttribute(clientName);
        final HtmlTextInput redirectURIInput = form.getInputByName("client_redirectURI");
        redirectURIInput.setValueAttribute(redirectURI);

        final HtmlButton button = form.getButtonByName("submit_button");
        final HtmlPage rpPage = button.click();
        
        return rpPage.getBody().getTextContent();
    }
    
    // Runs as AfterClass: Login to the OIDC Clients page + delete the created clients!
    private static void loginToClientsPageAndDeleteClient(String rpPort, String idpPort) throws Exception {
        String url = "https://localhost:" + rpPort + "/fediz-oidc/clients";
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
        String url = "https://localhost:" + getRpHttpsPort() + "/fediz-oidc/clients";
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
        Assert.assertEquals("http://127.0.1.1", redirectURI);
        
        // Now check the specific client page
        HtmlPage clientPage = webClient.getPage(url + "/" + clientId);
        HtmlTable clientTable = clientPage.getHtmlElementById("client");
        Assert.assertEquals(clientId, clientTable.getCellAt(1, 0).asText().trim());
        
        webClient.close();
    }
    
    /*
    @org.junit.Test
    public void testTemp() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fediz-oidc/clients";
        System.out.println("URL: " + url);
        Thread.sleep(60 * 1000);
    }
    */
    
    @org.junit.Test
    @org.junit.Ignore
    public void testOIDCLogin() throws Exception {
        
        String url = "https://localhost:" + getRpHttpsPort() + "/fediz-oidc/idp/authorize?";
        url += "client_id=xSzMefvgOwLflQ";
        url += "&redirect_uri=http://www.blah.apache.org";
        url += "&response_type=code";
        url += "&scope=openid";
        String user = "alice";
        String password = "ecila";
        
        // Login to the OIDC token endpoint + get the authorization code
        WebClient webClient = setupWebClient(user, password, getIdpHttpsPort());
        String authorizationCode = 
            loginAndGetAuthorizationCode(url, webClient);
        Assert.assertNotNull(authorizationCode);
        
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

        // Bit of a hack here to get the authorization code
        CodeWebConnectionWrapper wrapper = new CodeWebConnectionWrapper(webClient);
        
        try {
            button.click();
        } catch (Throwable t) {
            // expected
        }

        wrapper.close();
        return wrapper.getCode();
    }
    
    private static class CodeWebConnectionWrapper extends WebConnectionWrapper {

        private String code;
        
        public CodeWebConnectionWrapper(WebClient webClient) throws IllegalArgumentException {
            super(webClient);
        }
        
        public WebResponse getResponse(WebRequest request) throws IOException {
            WebResponse response = super.getResponse(request);
            String location = response.getResponseHeaderValue("Location");
            if (location.contains("code")) {
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
