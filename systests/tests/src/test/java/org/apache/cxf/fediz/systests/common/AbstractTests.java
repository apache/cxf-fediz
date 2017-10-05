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

package org.apache.cxf.fediz.systests.common;

import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.util.NameValuePair;
import com.gargoylesoftware.htmlunit.xml.XmlPage;

import org.apache.commons.io.IOUtils;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.Assert;
import org.junit.Test;

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

    @Test
    public void testAlice() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
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

    @Test
    public void testAliceUser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/user/fedservlet";
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

    @Test
    public void testAliceAdminNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/admin/fedservlet";
        String user = "alice";
        String password = "ecila";

        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }

    @Test
    public void testAliceManagerNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/manager/fedservlet";
        String user = "alice";
        String password = "ecila";

        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }

    @Test
    public void testAliceWrongPasswordNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
        String user = "alice";
        String password = "alice";

        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 401);
        }
    }

    @Test
    public void testBob() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
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

    @Test
    public void testBobUser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/user/fedservlet";
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

    @Test
    public void testBobManager() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/manager/fedservlet";
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

    @Test
    public void testBobAdmin() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/admin/fedservlet";
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

    @Test
    public void testTed() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
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

    @Test
    public void testTedUserNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/user/fedservlet";
        String user = "ted";
        String password = "det";

        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }

    @Test
    public void testTedAdminNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/admin/fedservlet";
        String user = "ted";
        String password = "det";

        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }

    @Test
    public void testTedManagerNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/manager/fedservlet";
        String user = "ted";
        String password = "det";

        try {
            HTTPTestUtils.login(url, user, password, getIdpHttpsPort());
            Assert.fail("Exception expected");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 403);
        }
    }

    @Test
    public void testRPMetadata() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort()
            + "/" + getServletContextName() + "/FederationMetadata/2007-06/FederationMetadata.xml";

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

    @Test
    public void testRPLogout() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
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
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                          || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));

        // 3. now we logout from RP
        String rpLogoutUrl = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/logout";

        HTTPTestUtils.logout(rpLogoutUrl, cookieManager);

        // 4. now we try to access the RP and idp without authentication but with the existing cookies
        // to see if we are really logged out

        webClient.close();
        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        final HtmlPage idpPage = webClient.getPage(url);

        Assert.assertEquals(401, idpPage.getWebResponse().getStatusCode());

        webClient.close();
    }

    @Test
    public void testRPLogoutViaAction() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
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
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                          || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));

        // 3. now we logout from RP
        String rpLogoutUrl = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet?wa=" + FederationConstants.ACTION_SIGNOUT;

        HTTPTestUtils.logout(rpLogoutUrl, cookieManager);

        // 4. now we try to access the RP and idp without authentication but with the existing cookies
        // to see if we are really logged out

        webClient.close();
        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        final HtmlPage idpPage = webClient.getPage(url);

        Assert.assertEquals(401, idpPage.getWebResponse().getStatusCode());

        webClient.close();
    }

    @Test
    public void testIdPLogout() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
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
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                          || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));

        // 3. now we logout from IdP
        String idpLogoutUrl = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/federation?wa="
            + FederationConstants.ACTION_SIGNOUT; //todo logout url on idp?!?

        HTTPTestUtils.logout(idpLogoutUrl, cookieManager);

        // 4. now we try to access the RP and idp without authentication but with the existing cookies
        // to see if we are really logged out

        webClient.close();
        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        final HtmlPage idpPage = webClient.getPage(url);

        Assert.assertEquals(401, idpPage.getWebResponse().getStatusCode());

        webClient.close();
    }

    @Test
    public void testIdPLogoutCleanup() throws Exception {

        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
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
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                          || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));

        // 3. now we logout from IdP
        String idpLogoutUrl = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/federation?wa="
            + FederationConstants.ACTION_SIGNOUT_CLEANUP;

        HTTPTestUtils.logoutCleanup(idpLogoutUrl, cookieManager);

        // 4. now we try to access the RP and idp without authentication but with the existing cookies
        // to see if we are really logged out

        webClient.close();
        webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        final HtmlPage idpPage = webClient.getPage(url);

        Assert.assertEquals(401, idpPage.getWebResponse().getStatusCode());

        webClient.close();
    }

    @Test
    public void testAliceModifiedSignature() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
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
            Assert.assertTrue(401 == ex.getStatusCode() || 403 == ex.getStatusCode());
        }

        webClient.close();
    }

    @Test
    public void testConcurrentRequests() throws Exception {

        String url1 = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
        String url2 = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/test.html";
        String user = "bob";
        String password = "bob";

        // Get the initial token
        CookieManager cookieManager = new CookieManager();
        final WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage1 = webClient.getPage(url1);
        final HtmlPage idpPage2 = webClient.getPage(url2);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage1.getTitleText());
        Assert.assertEquals("IDP SignIn Response Form", idpPage2.getTitleText());

        // Invoke back on the page1 RP
        final HtmlForm form = idpPage1.getFormByName("signinresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");
        final HtmlPage rpPage1 = button.click();
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage1.getTitleText())
                          || "WS Federation Systests Spring Examples".equals(rpPage1.getTitleText()));

        String bodyTextContent1 = rpPage1.getBody().getTextContent();

        Assert.assertTrue("Principal not " + user,
                          bodyTextContent1.contains("userPrincipal=" + user));

        // Invoke back on the page2 RP
        final HtmlForm form2 = idpPage2.getFormByName("signinresponseform");
        final HtmlSubmitInput button2 = form2.getInputByName("_eventId_submit");
        final HtmlPage rpPage2 = button2.click();
        String bodyTextContent2 = rpPage2.getBody().getTextContent();

        Assert.assertTrue("Unexpected content of RP page", bodyTextContent2.contains("Secure Test"));

        webClient.close();
    }

    @org.junit.Test
    public void testMaliciousRedirect() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
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
        HtmlPage rpPage = webClient.getPage(url);
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                          || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));

        // 3. Now a malicious user sends the client a URL with a bad "wreply" address to the IdP
        String maliciousURL = "https://www.apache.org/attack";
        String idpUrl
         = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/federation";
        idpUrl += "?wa=wsignin1.0&wreply=" + URLEncoder.encode(maliciousURL, "UTF-8");
        idpUrl += "&wtrealm=urn%3Aorg%3Aapache%3Acxf%3Afediz%3Afedizhelloworld";
        idpUrl += "&whr=urn%3Aorg%3Aapache%3Acxf%3Afediz%3Aidp%3Arealm-A";
        webClient.close();

        final WebClient webClient2 = new WebClient();
        webClient2.setCookieManager(cookieManager);
        webClient2.getOptions().setUseInsecureSSL(true);
        webClient2.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient2.getOptions().setJavaScriptEnabled(false);
        try {
            webClient2.getPage(idpUrl);
            Assert.fail("Failure expected on a bad wreply address");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 400);
        }
        webClient2.close();
    }

    @Test
    public void testEntityExpansionAttack() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
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

        String entity =
            IOUtils.toString(this.getClass().getClassLoader().getResource("entity.xml").openStream(), "UTF-8");
        String reference = "&m;";

        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                // Now modify the Signature
                String value = result.getAttributeNS(null, "value");
                value = entity + value;
                value = value.replace("alice", reference);
                result.setAttributeNS(null, "value", value);
            }
        }

        // Invoke back on the RP

        final HtmlForm form = idpPage.getFormByName("signinresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        try {
            button.click();
            Assert.fail("Failure expected on an entity expansion attack");
        } catch (FailingHttpStatusCodeException ex) {
            // expected
            Assert.assertTrue(401 == ex.getStatusCode() || 403 == ex.getStatusCode());
        }

        webClient.close();
    }

    @org.junit.Test
    public void testCSRFAttack() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
        csrfAttackTest(url);
    }

    protected void csrfAttackTest(String rpURL) throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        // 1. Log in as "alice"
        WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        final HtmlForm form = idpPage.getFormByName("signinresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button.click();
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                            || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));


        // 2. Log in as "bob" using another WebClient
        WebClient webClient2 = new WebClient();
        webClient2.getOptions().setUseInsecureSSL(true);
        webClient2.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials("bob", "bob"));

        webClient2.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage2 = webClient2.getPage(url);
        webClient2.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage2.getTitleText());

        // 3. Now instead of clicking on the form, send the form via alice's WebClient instead

        // Send with context...
        WebRequest request = new WebRequest(new URL(rpURL), HttpMethod.POST);
        request.setRequestParameters(new ArrayList<NameValuePair>());

        DomNodeList<DomElement> results = idpPage2.getElementsByTagName("input");

        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))
                || "wa".equals(result.getAttributeNS(null, "name"))
                || "wctx".equals(result.getAttributeNS(null, "name"))) {
                String value = result.getAttributeNS(null, "value");
                request.getRequestParameters().add(new NameValuePair(result.getAttributeNS(null, "name"), value));
            }
        }

        try {
            webClient.getPage(request);
            Assert.fail("Failure expected on a CSRF attack");
        } catch (FailingHttpStatusCodeException ex) {
            // expected
        }

        webClient.close();
        webClient2.close();

    }

}
