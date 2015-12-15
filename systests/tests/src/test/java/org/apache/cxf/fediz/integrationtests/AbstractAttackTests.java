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

import java.net.URLEncoder;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.junit.Assert;
import org.junit.Test;

/**
 * Some negative/attack tests for the IdP/RP
 */
public abstract class AbstractAttackTests {
    
    static final String TEST_WREQ = 
        "<RequestSecurityToken xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
        + "<TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV3.0</TokenType>"
        + "</RequestSecurityToken>";
    
    static {
        WSSConfig.init();
    }

    public AbstractAttackTests() {
        super();
    }

    public abstract String getServletContextName();
    
    public abstract String getIdpHttpsPort();

    public abstract String getRpHttpsPort();

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
            Assert.assertTrue(ex.getMessage().contains("401 Unauthorized")
                              || ex.getMessage().contains("401 Authentication Failed")
                              || ex.getMessage().contains("403 Forbidden"));
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
    
    // Send an unknown wreq value
    @org.junit.Test
    public void testBadWReq() throws Exception {
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/federation?";
        url += "wa=wsignin1.0";
        url += "&whr=urn:org:apache:cxf:fediz:idp:realm-A";
        url += "&wtrealm=urn:org:apache:cxf:fediz:fedizhelloworld";
        String wreply = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
        url += "&wreply=" + wreply;
        url += "&wreq=" + URLEncoder.encode(TEST_WREQ, "UTF-8");
        
        String user = "alice";
        String password = "ecila";
        
        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(url);
            Assert.fail("Failure expected on a bad wreq value");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 400);
        }
        
        webClient.close();
    }
}
