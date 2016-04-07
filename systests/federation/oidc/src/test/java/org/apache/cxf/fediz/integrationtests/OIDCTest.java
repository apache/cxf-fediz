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

package org.apache.cxf.fediz.integrationtests;


import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import org.w3c.dom.Element;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;
import com.gargoylesoftware.htmlunit.xml.XmlPage;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.tomcat7.FederationAuthenticator;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * This is a test for federation in the IdP. The RP application is configured to use a home realm of "realm b". The
 * client gets redirected to the IdP for "realm a", which in turn redirects to the IdP for "realm b", which is a 
 * OIDC IdP. The IdP for "realm a" will convert the signin request to a OIDC authorization code flow request. The 
 * IdP for realm b authenticates the user, who is then redirected back to the IdP for "realm a" to get a SAML token 
 * from the STS + then back to the application.
 */
public class OIDCTest {

    static String idpHttpsPort;
    static String idpOIDCHttpsPort;
    static String rpHttpsPort;
    
    private static Tomcat idpServer;
    private static Tomcat idpOIDCServer;
    private static Tomcat rpServer;
    
    @BeforeClass
    public static void init() {
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
        idpOIDCHttpsPort = System.getProperty("idp.oidc.https.port");
        Assert.assertNotNull("Property 'idp.oidc.https.port' null", idpOIDCHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        initIdp();
        initOIDCIdp();
        initRp();
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
    
    private static void initOIDCIdp() {
        try {
            idpOIDCServer = new Tomcat();
            idpOIDCServer.setPort(0);
            String currentDir = new File(".").getCanonicalPath();
            idpOIDCServer.setBaseDir(currentDir + File.separator + "target");
            
            idpOIDCServer.getHost().setAppBase("tomcat/idpoidc/webapps");
            idpOIDCServer.getHost().setAutoDeploy(true);
            idpOIDCServer.getHost().setDeployOnStartup(true);
            
            Connector httpsConnector = new Connector();
            httpsConnector.setPort(Integer.parseInt(idpOIDCHttpsPort));
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

            idpOIDCServer.getService().addConnector(httpsConnector);
            
            idpOIDCServer.addWebapp("/idp", "idpoidc");
            
            idpOIDCServer.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void initRp() {
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
            
            Context cxt = rpServer.addWebapp("/fedizhelloworld", "simpleWebapp");
            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(currentDir + File.separator + "target" + File.separator
                             + "test-classes" + File.separator + "fediz_config_oidc.xml");
            cxt.getPipeline().addValve(fa);
            
            rpServer.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
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

    public String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    public String getRpHttpsPort() {
        return rpHttpsPort;
    }
    
    public String getServletContextName() {
        return "fedizhelloworld";
    }
    
    @org.junit.Test
    @org.junit.Ignore
    public void testBrowser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        System.out.println("URL: " + url);
        Thread.sleep(60 * 1000);
    }
    
    @org.junit.Test
    public void testOIDC() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";
        
        final String bodyTextContent = 
            login(url, user, password, idpOIDCHttpsPort, idpHttpsPort);
        
        Assert.assertTrue("Principal not alice",
                          bodyTextContent.contains("userPrincipal=alice"));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          bodyTextContent.contains(claim + "=Alice"));
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          bodyTextContent.contains(claim + "=Smith"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
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
        
        // The decision page is returned as XML for some reason. So parse it and send a form response back.
        XmlPage oidcIdpConfirmationPage = webClient.getPage(url);
        
        Element clientId = (Element)oidcIdpConfirmationPage.getByXPath("//clientId").get(0);
        Element redirectUri = (Element)oidcIdpConfirmationPage.getByXPath("//redirectUri").get(0);
        Element scope = (Element)oidcIdpConfirmationPage.getByXPath("//proposedScope").get(0);
        Element state = (Element)oidcIdpConfirmationPage.getByXPath("//state").get(0);
        Element authenticityToken = (Element)oidcIdpConfirmationPage.getByXPath("//authenticityToken").get(0);
        Element replyTo = (Element)oidcIdpConfirmationPage.getByXPath("//replyTo").get(0);
        
        WebRequest request = new WebRequest(new URL(replyTo.getTextContent()), HttpMethod.POST);

        request.setRequestParameters(new ArrayList<NameValuePair>());
        request.getRequestParameters().add(new NameValuePair("client_id", clientId.getTextContent()));
        request.getRequestParameters().add(new NameValuePair("redirect_uri", redirectUri.getTextContent()));
        request.getRequestParameters().add(new NameValuePair("scope", scope.getTextContent()));
        request.getRequestParameters().add(new NameValuePair("state", state.getTextContent()));
        request.getRequestParameters().add(new NameValuePair("session_authenticity_token", 
                                                             authenticityToken.getTextContent()));
        request.getRequestParameters().add(new NameValuePair("oauthDecision", "allow"));

        HtmlPage idpPage = webClient.getPage(request);
        
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Now redirect back to the RP
        final HtmlForm form = idpPage.getFormByName("signinresponseform");

        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button.click();
        Assert.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        webClient.close();
        return rpPage.getBody().getTextContent();
    }
    
}
