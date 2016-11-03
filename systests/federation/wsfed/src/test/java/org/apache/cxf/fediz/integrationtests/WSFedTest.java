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

import javax.servlet.ServletException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.xml.XmlPage;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.tomcat7.FederationAuthenticator;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

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

    static String idpHttpsPort;
    static String idpRealmbHttpsPort;
    static String idpSamlSSOHttpsPort;
    static String rpHttpsPort;
    
    private static Tomcat idpServer;
    private static Tomcat idpRealmbServer;
    private static Tomcat idpSamlSSOServer;
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
        idpRealmbHttpsPort = System.getProperty("idp.realmb.https.port");
        Assert.assertNotNull("Property 'idp.realmb.https.port' null", idpRealmbHttpsPort);
        idpSamlSSOHttpsPort = System.getProperty("idp.samlsso.https.port");
        Assert.assertNotNull("Property 'idp.samlsso.https.port' null", idpSamlSSOHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        idpServer = startServer(true, false, false, idpHttpsPort);
        idpRealmbServer = startServer(false, true, false, idpRealmbHttpsPort);
        idpSamlSSOServer = startServer(false, false, true, idpSamlSSOHttpsPort);
        rpServer = startServer(false, false, false, rpHttpsPort);
    }
    
    private static Tomcat startServer(boolean idp, boolean realmb, boolean samlSSOIdP, String port) 
        throws ServletException, LifecycleException, IOException {
        Tomcat server = new Tomcat();
        server.setPort(0);
        String currentDir = new File(".").getCanonicalPath();
        String baseDir = currentDir + File.separator + "target";
        server.setBaseDir(baseDir);

        if (idp) {
            server.getHost().setAppBase("tomcat/idp/webapps");
        } else if (realmb) {
            server.getHost().setAppBase("tomcat/idprealmb/webapps");
        } else if (samlSSOIdP) {
            server.getHost().setAppBase("tomcat/idpsamlsso/webapps");
        } else {
            server.getHost().setAppBase("tomcat/rp/webapps");
        }
        server.getHost().setAutoDeploy(true);
        server.getHost().setDeployOnStartup(true);

        Connector httpsConnector = new Connector();
        httpsConnector.setPort(Integer.parseInt(port));
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

        server.getService().addConnector(httpsConnector);

        if (idp) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts");
            server.addWebapp("/fediz-idp-sts", stsWebapp.getAbsolutePath());
    
            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp");
            server.addWebapp("/fediz-idp", idpWebapp.getAbsolutePath());
        } else if (realmb) {
            File stsWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-sts-realmb");
            server.addWebapp("/fediz-idp-sts-realmb", stsWebapp.getAbsolutePath());
    
            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "fediz-idp-realmb");
            server.addWebapp("/fediz-idp-realmb", idpWebapp.getAbsolutePath());
        } else if (samlSSOIdP) {
            File idpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "idpsaml");
            server.addWebapp("/idp", idpWebapp.getAbsolutePath());
        } else {
            File rpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "simpleWebapp");
            Context cxt = server.addWebapp("/wsfed", rpWebapp.getAbsolutePath());
            
            FederationAuthenticator fa = new FederationAuthenticator();
            fa.setConfigFile(currentDir + File.separator + "target" + File.separator
                             + "test-classes" + File.separator + "fediz_config_wsfed.xml");
            cxt.getPipeline().addValve(fa);
            
            rpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "simpleWebapp");
            cxt = server.addWebapp("/samlsso", rpWebapp.getAbsolutePath());
            cxt.getPipeline().addValve(fa);
            
            rpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "simpleWebapp");
            cxt = server.addWebapp("/samlssocustom", rpWebapp.getAbsolutePath());
            cxt.getPipeline().addValve(fa);
            
            rpWebapp = new File(baseDir + File.separator + server.getHost().getAppBase(), "simpleWebapp");
            cxt = server.addWebapp("/samlssocustompost", rpWebapp.getAbsolutePath());
            cxt.getPipeline().addValve(fa);
        }

        server.start();

        return server;
    }
    
    @AfterClass
    public static void cleanup() {
        shutdownServer(idpServer);
        shutdownServer(idpRealmbServer);
        shutdownServer(idpSamlSSOServer);
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
        String url = "https://localhost:" + getRpHttpsPort() + "/wsfed/secure/fedservlet";
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
    
    @org.junit.Test
    public void testSAMLSSOFedizIdP() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlsso/secure/fedservlet";
        // System.out.println(url);
        // Thread.sleep(60 * 2 * 1000);
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";
        
        final String bodyTextContent = 
            login(url, user, password, getIdpRealmbHttpsPort(), getIdpHttpsPort(), true);
        
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
    
    @org.junit.Test
    public void testSAMLSSOCustom() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlssocustom/secure/fedservlet";
        // System.out.println("URL: " + url);
        // Thread.sleep(60 * 2 * 1000);
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";
        
        final String bodyTextContent = 
            login(url, user, password, idpSamlSSOHttpsPort, idpHttpsPort, false);
        
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
    
    @org.junit.Test
    public void testSAMLSSOCustomPostBinding() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/samlssocustompost/secure/fedservlet";
        // System.out.println("URL: " + url);
        // Thread.sleep(60 * 2 * 1000);
        String user = "ALICE";  // realm b credentials
        String password = "ECILA";
        
        final String bodyTextContent = 
            login(url, user, password, idpSamlSSOHttpsPort, idpHttpsPort, true);
        
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
    
    @Test
    public void testSAMLSSOIdPServiceMetadata() throws Exception {
        String url = "https://localhost:" + getIdpHttpsPort()
            + "/fediz-idp/metadata/urn:org:apache:cxf:fediz:idp:realm-B";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setSSLClientCertificate(
            this.getClass().getClassLoader().getResource("client.jks"), "storepass", "jks");

        final XmlPage rpPage = webClient.getPage(url);
        final String xmlContent = rpPage.asXml();
        Assert.assertTrue(xmlContent.startsWith("<md:EntityDescriptor"));

        // Now validate the Signature
        Document doc = rpPage.getXmlDocument();

        doc.getDocumentElement().setIdAttributeNS(null, "ID", true);

        Node signatureNode =
            DOMUtils.getChild(doc.getDocumentElement(), "Signature");
        Assert.assertNotNull(signatureNode);

        XMLSignature signature = new XMLSignature((Element)signatureNode, "");
        KeyInfo ki = signature.getKeyInfo();
        Assert.assertNotNull(ki);
        Assert.assertNotNull(ki.getX509Certificate());

        Assert.assertTrue(signature.checkSignatureValue(ki.getX509Certificate()));

        webClient.close();
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
        final HtmlForm form = idpPage.getFormByName("signinresponseform");

        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button.click();
        Assert.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        webClient.close();
        return rpPage.getBody().getTextContent();
    }
    
}
