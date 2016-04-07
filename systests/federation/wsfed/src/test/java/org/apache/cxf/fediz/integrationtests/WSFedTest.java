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
import java.net.URLEncoder;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

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
 * client gets redirected to the IdP for "realm a", which in turn redirects to the IdP for "realm b". The user 
 * authenticates + is redirected back to the IdP for "realm a" to get a SAML token from the STS + then back to the
 * application.
 */
public class WSFedTest {

    static String idpHttpsPort;
    static String idpRealmbHttpsPort;
    static String rpHttpsPort;
    
    private static Tomcat idpServer;
    private static Tomcat idpRealmbServer;
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
        idpRealmbHttpsPort = System.getProperty("idp.realmb.https.port");
        Assert.assertNotNull("Property 'idp.realmb.https.port' null", idpRealmbHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        initIdp();
        initRealmbIdp();
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
    
    private static void initRealmbIdp() {
        try {
            idpRealmbServer = new Tomcat();
            idpRealmbServer.setPort(0);
            String currentDir = new File(".").getCanonicalPath();
            idpRealmbServer.setBaseDir(currentDir + File.separator + "target");
            
            idpRealmbServer.getHost().setAppBase("tomcat/idprealmb/webapps");
            idpRealmbServer.getHost().setAutoDeploy(true);
            idpRealmbServer.getHost().setDeployOnStartup(true);
            
            Connector httpsConnector = new Connector();
            httpsConnector.setPort(Integer.parseInt(idpRealmbHttpsPort));
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

            idpRealmbServer.getService().addConnector(httpsConnector);
            
            idpRealmbServer.addWebapp("/fediz-idp-sts-realmb", "fediz-idp-sts-realmb");
            idpRealmbServer.addWebapp("/fediz-idp-realmb", "fediz-idp-realmb");
            
            idpRealmbServer.start();
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
            
            //Context ctx =
            Context cxt = rpServer.addWebapp("/fedizhelloworld", "simpleWebapp");
            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(currentDir + File.separator + "target" + File.separator
                             + "test-classes" + File.separator + "fediz_config_wsfed.xml");
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
    public void testWSFed() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        // System.out.println(url);
        // Thread.sleep(60 * 2 * 1000);
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";
        
        final String bodyTextContent = 
            login(url, user, password, getIdpRealmbHttpsPort(), idpHttpsPort);
        
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
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());
        
        // For some reason, redirecting back to the IdP for "realm a" is not working with htmlunit. So extract
        // the parameters manually from the form, and access the IdP for "realm a" with them
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String wresult = null;
        String wa = "wsignin1.0";
        String wctx = null;
        String wtrealm = null;
        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                wresult = result.getAttributeNS(null, "value");
            } else if ("wctx".equals(result.getAttributeNS(null, "name"))) {
                wctx = result.getAttributeNS(null, "value");
            } else if ("wtrealm".equals(result.getAttributeNS(null, "name"))) {
                wtrealm = result.getAttributeNS(null, "value");
            }
        }
        Assert.assertTrue(wctx != null && wresult != null && wtrealm != null);
        webClient.close();

        // Invoke on the IdP for "realm a"
        final WebClient webClient2 = new WebClient();
        webClient2.setCookieManager(cookieManager);
        webClient2.getOptions().setUseInsecureSSL(true);
        
        String url2 = "https://localhost:" + rpIdpPort + "/fediz-idp/federation?";
        url2 += "wctx=" + wctx + "&";
        url2 += "wa=" + wa + "&";
        url2 += "wtrealm=" + URLEncoder.encode(wtrealm, "UTF8") + "&";
        url2 += "wresult=" + URLEncoder.encode(wresult, "UTF8") + "&";
        
        webClient2.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage2 = webClient2.getPage(url2);
        webClient2.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage2.getTitleText());
        
        // Now redirect back to the RP
        final HtmlForm form2 = idpPage2.getFormByName("signinresponseform");
        
        final HtmlSubmitInput button2 = form2.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button2.click();
        Assert.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        webClient2.close();
        return rpPage.getBody().getTextContent();
    }
    
    
}
