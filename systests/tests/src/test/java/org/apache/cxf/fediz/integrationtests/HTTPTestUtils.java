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

import java.io.IOException;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.junit.Assert;

/**
 * Some basic HTTP-based functionality for use in the tests
 */
public final class HTTPTestUtils {

    private HTTPTestUtils() {
        // complete
    }

    public static String login(String url, String user, String password, String idpPort,
                               String formName) throws IOException {
        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(idpPort)),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        final HtmlForm form = idpPage.getFormByName(formName);
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        final HtmlPage rpPage = button.click();
        Assert.assertTrue("WS Federation Systests Examples".equals(rpPage.getTitleText())
                            || "WS Federation Systests Spring Examples".equals(rpPage.getTitleText()));

        // webClient.close();
        return rpPage.getBody().getTextContent();
    }

    public static String loginWithCookieManager(String url, String user, String password,
                                                String idpPort, CookieManager cookieManager) throws IOException {
        final WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(idpPort)),
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

        // webClient.close();
        return rpPage.getBody().getTextContent();
    }

    public static void logout(String url, CookieManager cookieManager) throws IOException {
        final WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        final HtmlPage idpPage = webClient.getPage(url);

        Assert.assertEquals("IDP SignOut Confirmation Response Page", idpPage.getTitleText());

        final HtmlForm form = idpPage.getFormByName("signoutconfirmationresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");
        final HtmlPage idpLogoutPage = button.click();

        DomNodeList<DomElement> images = idpLogoutPage.getElementsByTagName("img");
        Assert.assertEquals(1, images.getLength());
        for (int i = 0; i < images.size(); i++) {
            DomElement domElement = images.get(i);
            String imgSrc = domElement.getAttribute("src");

            //we should get a fault if the image isn't available.
            webClient.getPage(imgSrc);
        }

        // webClient.close();
    }

    public static void logoutCleanup(String url, CookieManager cookieManager) throws IOException {
        final WebClient webClient = new WebClient();
        webClient.setCookieManager(cookieManager);
        webClient.getOptions().setUseInsecureSSL(true);
        final HtmlPage idpPage = webClient.getPage(url);

        Assert.assertEquals("IDP SignOut Response Page", idpPage.getTitleText());

        Assert.assertTrue(idpPage.asText().contains("CXF Fediz IDP successful logout"));

        DomNodeList<DomElement> images = idpPage.getElementsByTagName("img");
        Assert.assertEquals(1, images.getLength());
        for (int i = 0; i < images.size(); i++) {
            DomElement domElement = images.get(i);
            String imgSrc = domElement.getAttribute("src");

            //we should get a fault if the image isn't available.
            webClient.getPage(imgSrc);
        }

        // webClient.close();
    }

}
