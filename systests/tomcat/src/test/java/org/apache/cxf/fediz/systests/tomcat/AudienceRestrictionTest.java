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


import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

/**
 * A test to make sure that audience restriction validation is working correctly in the plugin.
 */
public class AudienceRestrictionTest {

    private static final String SERVLET_CONTEXT_NAME = "fedizhelloworld_audrestr";

    @BeforeClass
    public static void init() throws Exception {
        TomcatLauncher.startServer(SERVLET_CONTEXT_NAME);
    }

    @AfterClass
    public static void cleanup() throws Exception {
        TomcatLauncher.shutdownServer();
    }

    @org.junit.Test
    public void testSAMLTokenWithNonMatchingAudienceRestriction() throws Exception {
        String url = "https://localhost:" + TomcatLauncher.getRpHttpsPort() + '/' + SERVLET_CONTEXT_NAME
                + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(TomcatLauncher.getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage idpPage = webClient.getPage(url);
        webClient.getOptions().setJavaScriptEnabled(true);
        Assert.assertEquals("IDP SignIn Response Form", idpPage.getTitleText());

        final HtmlForm form = idpPage.getFormByName("signinresponseform");
        final HtmlSubmitInput button = form.getInputByName("_eventId_submit");

        try {
            button.click();
            Assert.fail("Failure expected on a bad audience restriction value");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 401);
        }

        webClient.close();
    }

}
