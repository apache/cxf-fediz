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

import com.gargoylesoftware.htmlunit.WebClient;
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
    
    public static String login(String url, String user, String password, String idpPort) throws IOException {
        final WebClient webClient = new WebClient();
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
        Assert.assertEquals("WS Federation Systests Examples", rpPage.getTitleText());

        return rpPage.getBody().getTextContent();
    }
    
    public static String loginForSAMLSSO(String url, String user, String password, String idpPort) throws IOException {
        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(idpPort)),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        final HtmlPage rpPage = webClient.getPage(url);

        return rpPage.getBody().getTextContent();
    }

    /**
     * Same as sendHttpGet above, except that we return the HttpClient so that it can
     * subsequently be re-used (for e.g. logout)
    public static CloseableHttpClient sendHttpGetForSignIn(String url, String user, String password, 
                                                           int returnCodeIDP, int returnCodeRP, int idpPort)
        throws Exception {

        CloseableHttpClient httpClient = null;
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(
                                     new AuthScope("localhost", idpPort), 
                                     new UsernamePasswordCredentials(user, password));

        KeyStore trustStore  = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream instream = new FileInputStream(new File("./target/test-classes/client.jks"));
        try {
            trustStore.load(instream, "clientpass".toCharArray());
        } finally {
            try {
                instream.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
        sslContextBuilder.loadTrustMaterial(trustStore, new TrustSelfSignedStrategy());
        sslContextBuilder.loadKeyMaterial(trustStore, "clientpass".toCharArray());

        SSLContext sslContext = sslContextBuilder.build();
        SSLConnectionSocketFactory sslSocketFactory = 
            new SSLConnectionSocketFactory(sslContext);

        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        httpClientBuilder.setDefaultCredentialsProvider(credsProvider);
        httpClientBuilder.setSSLSocketFactory(sslSocketFactory);
        httpClientBuilder.setRedirectStrategy(new LaxRedirectStrategy());

        httpClient = httpClientBuilder.build();

        HttpGet httpget = new HttpGet(url);

        HttpResponse response = httpClient.execute(httpget);
        HttpEntity entity = response.getEntity();

        Assert.assertTrue("IDP HTTP Response code: " + response.getStatusLine().getStatusCode()
                          + " [Expected: " + returnCodeIDP + "]",
                          returnCodeIDP == response.getStatusLine().getStatusCode());

        if (response.getStatusLine().getStatusCode() != 200) {
            return null;
        }

        //            Redirect to a POST is not supported without user interaction
        //            http://www.ietf.org/rfc/rfc2616.txt
        //            If the 301 status code is received in response to a request other
        //            than GET or HEAD, the user agent MUST NOT automatically redirect the
        //            request unless it can be confirmed by the user, since this might
        //            change the conditions under which the request was issued.

        Source source = new Source(EntityUtils.toString(entity));
        List <NameValuePair> nvps = new ArrayList <NameValuePair>();
        FormFields formFields = source.getFormFields();

        List<Element> forms = source.getAllElements(HTMLElementName.FORM);
        Assert.assertEquals("Only one form expected but got " + forms.size(), 1, forms.size());
        String postUrl = forms.get(0).getAttributeValue("action");

        Assert.assertNotNull("Form field 'wa' not found", formFields.get("wa"));
        Assert.assertNotNull("Form field 'wresult' not found", formFields.get("wresult"));

        for (FormField formField : formFields) {
            if (formField.getUserValueCount() != 0) {
                nvps.add(new BasicNameValuePair(formField.getName(),
                                                formField.getValues().get(0)));
            }
        } 
        HttpPost httppost = new HttpPost(postUrl);
        httppost.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8));

        response = httpClient.execute(httppost);

        entity = response.getEntity();
        Assert.assertTrue("RP HTTP Response code: " + response.getStatusLine().getStatusCode()
                          + " [Expected: " + returnCodeRP + "]",
                          returnCodeRP == response.getStatusLine().getStatusCode());

        String responseStr = EntityUtils.toString(entity);
        Assert.assertTrue("Principal not " + user, responseStr.indexOf("userPrincipal=" + user) > 0);

        return httpClient;
    }

    public static String sendHttpGetForSignOut(CloseableHttpClient httpClient, String url,
                                               int returnCodeIDP, int returnCodeRP, int idpPort)
        throws Exception {
        try {
            // logout to service provider
            HttpGet httpget = new HttpGet(url);

            HttpResponse response = httpClient.execute(httpget);
            HttpEntity entity = response.getEntity();

            String parsedEntity = EntityUtils.toString(entity);
            Assert.assertTrue(parsedEntity.contains("Logout from the following realms"));
            Source source = new Source(parsedEntity);
            List <NameValuePair> nvps = new ArrayList <NameValuePair>();
            FormFields formFields = source.getFormFields();

            List<Element> forms = source.getAllElements(HTMLElementName.FORM);
            Assert.assertEquals("Only one form expected but got " + forms.size(), 1, forms.size());
            String postUrl = forms.get(0).getAttributeValue("action");

            Assert.assertNotNull("Form field 'wa' not found", formFields.get("wa"));

            for (FormField formField : formFields) {
                if (formField.getUserValueCount() != 0) {
                    nvps.add(new BasicNameValuePair(formField.getName(),
                                                    formField.getValues().get(0)));
                }
            } 

            // Now send logout form to IdP
            nvps.add(new BasicNameValuePair("_eventId_submit", "Logout"));

            HttpPost httppost = 
                new HttpPost("https://localhost:" + idpPort + "/" + postUrl);
            httppost.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8));

            response = httpClient.execute(httppost);
            entity = response.getEntity();

            return EntityUtils.toString(entity);
        } finally {
            if (httpClient != null) {
                httpClient.close();
            }
        }
    }
    */
}
