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

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.junit.Assert;
import org.junit.Test;

/**
 * Some tests for token expiry
 */
public abstract class AbstractExpiryTests {

    static {
        WSSConfig.init();
    }

    public AbstractExpiryTests() {
        super();
    }

    public abstract String getServletContextName();

    public abstract String getIdpHttpsPort();

    public abstract String getRpHttpsPort();

    // A test to make sure that when a token expires (+ the plugin is configured to enforce token expiration), that the
    // redirect back to the IdP works properly.
    @Test
    public void testPluginTokenExpiry() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        // 1. Login
        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        HtmlForm form = idpPage.getFormByName("signinresponseform");
        HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        HtmlPage rpPage = button.click();
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                            || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));

        String bodyTextContent = rpPage.getBody().getTextContent();
        verifyApplication(user, bodyTextContent);

        // 2. Sleep to expire the token
        System.out.println("Sleeping...");
        Thread.sleep(8L * 1000L);

        // 3. Now invoke again on the endpoint
        webClient.getOptions().setJavaScriptEnabled(false);
        idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        form = idpPage.getFormByName("signinresponseform");
        button = form.getInputByName("_eventId_submit");

        rpPage = button.click();
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                            || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));

        bodyTextContent = rpPage.getBody().getTextContent();
        verifyApplication(user, bodyTextContent);

        webClient.close();
    }

    // Test what happens when the IdP token expires. This is "mocked" by setting wfresh to "0" in the
    // plugin configuration.
    @org.junit.Test
    public void testIdPTokenExpiry() throws Exception {
        // 1. Login
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName()
            + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        CookieManager cookieManager = new CookieManager();

        // 1. Login
        HTTPTestUtils.loginWithCookieManager(url, user, password, getIdpHttpsPort(), "signinresponseform", cookieManager);

        // 2. Sign out of the service (but not the Idp)
        final WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getPage(url + "?wa=wsignoutcleanup1.0");
        webClient.close();

        // 3. Sign back in to the service provider. This time it will get a new IdP token due to wfresh=0.
        HTTPTestUtils.loginWithCookieManager(url, user, password, getIdpHttpsPort(), "signinresponseform", cookieManager);
    }

    private void verifyApplication(String user, String bodyTextContent) {
        Assert.assertTrue("Principal not " + user,
                          bodyTextContent.contains("userPrincipal=" + user));
        Assert.assertTrue("User " + user + " does not have role Admin",
                          bodyTextContent.contains("role:Admin=false"));
        Assert.assertTrue("User " + user + " does not have role Manager",
                          bodyTextContent.contains("role:Manager=false"));
        Assert.assertTrue("User " + user + " must have role User",
                          bodyTextContent.contains("role:User=true"));
    }

}