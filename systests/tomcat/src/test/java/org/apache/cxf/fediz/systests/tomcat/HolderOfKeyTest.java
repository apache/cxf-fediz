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

package org.apache.cxf.fediz.systests.tomcat;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;

/**
 * A test for sending a "PublicKey" KeyType request to the IdP via the "wreq" parameter. This
 * will cause the IdP/STS to issue a "HolderOfKey" SAML Assertion.
 */
public class HolderOfKeyTest {

    private static final String SERVLET_CONTEXT_NAME = "fedizhelloworld_hok";

    @BeforeAll
    public static void init() throws Exception {
        TomcatLauncher.startServer(SERVLET_CONTEXT_NAME);
    }

    @AfterAll
    public static void cleanup() throws Exception {
        TomcatLauncher.shutdownServer();
    }

    @org.junit.jupiter.api.Test
    public void testHolderOfKey() throws Exception {
        String url = "https://localhost:" + TomcatLauncher.getRpHttpsPort() + '/' + SERVLET_CONTEXT_NAME
                + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setSSLClientCertificate(
            this.getClass().getClassLoader().getResource("client.jks"), "storepass", "jks");
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(TomcatLauncher.getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assertions.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        final HtmlForm form = idpPage.getFormByName("signinresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        // Test the Subject Confirmation method here
        DomNodeList<DomElement> results = idpPage.getElementsByTagName("input");

        String wresult = null;
        for (DomElement result : results) {
            if ("wresult".equals(result.getAttributeNS(null, "name"))) {
                wresult = result.getAttributeNS(null, "value");
                break;
            }
        }
        Assertions.assertTrue(wresult != null
            && wresult.contains("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"));


        final HtmlPage rpPage = button.click();
        Assertions.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        final String bodyTextContent = rpPage.getBody().getTextContent();
        Assertions.assertTrue(bodyTextContent.contains("userPrincipal=" + user), "Principal not " + user);
        Assertions.assertTrue(bodyTextContent.contains("role:Admin=false"),
                "User " + user + " does not have role Admin");
        Assertions.assertTrue(bodyTextContent.contains("role:Manager=false"),
                "User " + user + " does not have role Manager");
        Assertions.assertTrue(bodyTextContent.contains("role:User=true"),
                "User " + user + " must have role User");

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assertions.assertTrue(bodyTextContent.contains(claim + "=Alice"),
                "User " + user + " claim " + claim + " is not 'Alice'");
        claim = ClaimTypes.LASTNAME.toString();
        Assertions.assertTrue(bodyTextContent.contains(claim + "=Smith"),
                "User " + user + " claim " + claim + " is not 'Smith'");
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assertions.assertTrue(bodyTextContent.contains(claim + "=alice@realma.org"),
                "User " + user + " claim " + claim + " is not 'alice@realma.org'");

        webClient.close();
    }

}
