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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.xml.XmlPage;

import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.Assert;

public abstract class AbstractTests {
    
    static {
        WSSConfig.init();
    }

    public AbstractTests() {
        super();
    }

    public abstract String getServletContextName();
    
    public abstract String getIdpHttpsPort();

    public abstract String getRpHttpsPort();

    @org.junit.Test
    public void testAlice() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "ecila";
        
        final String bodyTextContent = 
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
        
        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
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
    public void testAliceUser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "alice";
        String password = "ecila";
        
        final String bodyTextContent = 
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());

        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));
    }
    
    @org.junit.Test
    public void testAliceAdminNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "alice";
        String password = "ecila";
        
        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }
    
    @org.junit.Test
    public void testAliceManagerNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "alice";
        String password = "ecila";
        
        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }

    @org.junit.Test
    public void testAliceWrongPasswordNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "alice";
        
        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 401);
        }
    }

    @org.junit.Test
    public void testBob() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "bob";
        String password = "bob";
        
        final String bodyTextContent = 
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());

        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=true"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=true"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Bob'",
                          bodyTextContent.contains(claim + "=Bob"));
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Windsor'",
                          bodyTextContent.contains(claim + "=Windsor"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'bobwindsor@realma.org'",
                          bodyTextContent.contains(claim + "=bobwindsor@realma.org"));
    }
    
    @org.junit.Test
    public void testBobUser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "bob";
        String password = "bob";
        
        final String bodyTextContent = 
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());

        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=true"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=true"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));
    }
    
    @org.junit.Test
    public void testBobManager() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "bob";
        String password = "bob";
        
        final String bodyTextContent = 
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());

        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=true"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=true"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));
    }
    
    @org.junit.Test
    public void testBobAdmin() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "bob";
        String password = "bob";
        
        final String bodyTextContent = 
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());

        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=true"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=true"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));
    }

    @org.junit.Test
    public void testTed() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "ted";
        String password = "det";
        
        final String bodyTextContent = 
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());

        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=false"));

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Ted'",
                          bodyTextContent.contains(claim + "=Ted"));
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Cooper'",
                          bodyTextContent.contains(claim + "=Cooper"));
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'tcooper@realma.org'",
                          bodyTextContent.contains(claim + "=tcooper@realma.org"));
    }
    
    @org.junit.Test
    public void testTedUserNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "ted";
        String password = "det";
        
        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }

    @org.junit.Test
    public void testTedAdminNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "ted";
        String password = "det";
        
        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }
    
    @org.junit.Test
    public void testTedManagerNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "ted";
        String password = "det";
        
        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }

    @org.junit.Test
    public void testRPMetadata() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() 
            + "/fedizhelloworld/FederationMetadata/2007-06/FederationMetadata.xml";

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
    }
    
    @org.junit.Test
    public void testIdPMetadata() throws Exception {
        String url = "https://localhost:" + getIdpHttpsPort() 
            + "/fediz-idp/FederationMetadata/2007-06/FederationMetadata.xml";

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
    }
    
    @org.junit.Test
    public void testRPLogout() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        CookieManager cookieManager = new CookieManager();
        
        // 1. Login
        HTTPTestUtils.loginWithCookieManager(url, user, password, getIdpHttpsPort(), cookieManager);
        
        // 2. Now we should have a cookie from the RP and IdP and should be able to do
        // subsequent requests without authenticate again. Lets test this first.
        WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        final HtmlPage rpPage = webClient.getPage(url);
        Assert.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        // 3. now we logout from RP
        String rpLogoutUrl = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/logout";

        HTTPTestUtils.logout(rpLogoutUrl, cookieManager);

        // 4. now we try to access the RP and idp without authentication but with the existing cookies
        // to see if we are really logged out
        String rpUrl = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";

        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        final HtmlPage idpPage = webClient.getPage(rpUrl);

        Assert.assertEquals(401, idpPage.getWebResponse().getStatusCode());
    }
    
    @org.junit.Test
    public void testIdPLogout() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        CookieManager cookieManager = new CookieManager();
        
        // 1. Login
        HTTPTestUtils.loginWithCookieManager(url, user, password, getIdpHttpsPort(), cookieManager);
       
        // 2. Now we should have a cookie from the RP and IdP and should be able to do
        // subsequent requests without authenticate again. Lets test this first.
        WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        final HtmlPage rpPage = webClient.getPage(url);
        Assert.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());
        
        // 3. now we logout from IdP
        String idpLogoutUrl = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/federation?wa="
            + FederationConstants.ACTION_SIGNOUT; //todo logout url on idp?!?

        HTTPTestUtils.logout(idpLogoutUrl, cookieManager);

        // 4. now we try to access the RP and idp without authentication but with the existing cookies
        // to see if we are really logged out
        String rpUrl = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";

        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        final HtmlPage idpPage = webClient.getPage(rpUrl);

        Assert.assertEquals(401, idpPage.getWebResponse().getStatusCode());
    }
    
    @org.junit.Test
    public void testIdPLogoutCleanup() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        CookieManager cookieManager = new CookieManager();
        
        // 1. Login
        HTTPTestUtils.loginWithCookieManager(url, user, password, getIdpHttpsPort(), cookieManager);
       
        // 2. Now we should have a cookie from the RP and IdP and should be able to do
        // subsequent requests without authenticate again. Lets test this first.
        WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        final HtmlPage rpPage = webClient.getPage(url);
        Assert.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());
        
        // 3. now we logout from IdP
        String idpLogoutUrl = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/federation?wa="
            + FederationConstants.ACTION_SIGNOUT_CLEANUP;

        HTTPTestUtils.logoutCleanup(idpLogoutUrl, cookieManager);

        // 4. now we try to access the RP and idp without authentication but with the existing cookies
        // to see if we are really logged out
        String rpUrl = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";

        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        final HtmlPage idpPage = webClient.getPage(rpUrl);

        Assert.assertEquals(401, idpPage.getWebResponse().getStatusCode());
    }
    
    @org.junit.Test
    public void testAliceModifiedSignature() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "ecila";
        
        // Get the initial token
        CookieManager cookieManager = new CookieManager();
        final WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        // Parse the form to get the token (wresult)
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                // Now modify the Signature
                String value = result.getAttributeNS(null, "value");
                value = value.replace("alice", "bob");
                result.setAttributeNS(null, "value", value);
            }
        }
        
        // Invoke back on the RP
        
        final HtmlForm form = idpPage.getFormByName("signinresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        try {
            button.click();
            Assert.fail("Failure expected on a modified signature");
        } catch (FailingHttpStatusCodeException ex) {
            // expected
            Assert.assertTrue(ex.getMessage().contains("401 Unauthorized")
                              || ex.getMessage().contains("401 Authentication Failed")
                              || ex.getMessage().contains("403 Forbidden"));
        }

    }
}
