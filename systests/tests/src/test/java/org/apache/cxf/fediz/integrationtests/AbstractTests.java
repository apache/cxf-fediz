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
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.FormField;
import net.htmlparser.jericho.FormFields;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.Assert;

public abstract class AbstractTests {

    public AbstractTests() {
        super();
    }

    public abstract String getIdpHttpsPort();

    public abstract String getRpHttpsPort();
    
    public abstract String getServletContextName();

    @org.junit.Test
    public void testUserAlice() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
        String user = "alice";
        String password = "ecila";
        String response = sendHttpGet(url, user, password);

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=false") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=false") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          response.indexOf(claim + "=Alice") > 0);
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          response.indexOf(claim + "=Smith") > 0);
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'alice@mycompany.org'",
                          response.indexOf(claim + "=alice@mycompany.org") > 0);
        
        Assert.assertTrue("Login token missing in SecurityTokenThreadLocal",
                          response.indexOf("loginToken=FOUND{SecurityTokenThreadLocal}") > 0);
        
        Assert.assertTrue("Login token missing in SecurityTokenThreadLocal",
                          response.indexOf("loginToken=FOUND{FederationPrincipal}") > 0);

    }

    @org.junit.Test
    public void testUserBob() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = sendHttpGet(url, user, password);

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=true") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=true") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Bob'",
                          response.indexOf(claim + "=Bob") > 0);
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Windsor'",
                          response.indexOf(claim + "=Windsor") > 0);
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'bobwindsor@idp.org'",
                          response.indexOf(claim + "=bobwindsor@idp.org") > 0);
        
        Assert.assertTrue("Login token missing in SecurityTokenThreadLocal",
                          response.indexOf("loginToken=FOUND{SecurityTokenThreadLocal}") > 0);
        
        Assert.assertTrue("Login token missing in SecurityTokenThreadLocal",
                          response.indexOf("loginToken=FOUND{FederationPrincipal}") > 0);
    }

    @org.junit.Test
    public void testUserTed() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
        String user = "ted";
        String password = "det";
        String response = sendHttpGet(url, user, password);

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=false") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=false") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=false") > 0);

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Ted'",
                          response.indexOf(claim + "=Ted") > 0);
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Cooper'",
                          response.indexOf(claim + "=Cooper") > 0);
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'tcooper@hereiam.org'",
                          response.indexOf(claim + "=tcooper@hereiam.org") > 0);
        
        Assert.assertTrue("Login token missing in SecurityTokenThreadLocal",
                          response.indexOf("loginToken=FOUND{SecurityTokenThreadLocal}") > 0);
        
        Assert.assertTrue("Login token missing in SecurityTokenThreadLocal",
                          response.indexOf("loginToken=FOUND{FederationPrincipal}") > 0);
    }

    @org.junit.Test
    public void testUserAliceNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/admin/fedservlet";
        String user = "alice";
        String password = "ecila";
        sendHttpGet(url, user, password, 200, 403);        
    }

    @org.junit.Ignore
    @org.junit.Test
    public void testUserAliceWrongPassword() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/fedservlet";
        String user = "alice";
        String password = "alice";
        //[TODO] Fix IDP return code from 500 to 401
        sendHttpGet(url, user, password, 500, 0);        
    }

    @org.junit.Test
    public void testUserTedNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/"
            + getServletContextName() + "/secure/admin/fedservlet";
        String user = "ted";
        String password = "det";
        sendHttpGet(url, user, password, 200, 403);        
    }

    private String sendHttpGet(String url, String user, String password) throws Exception {
        return sendHttpGet(url, user, password, 200, 200);
    }

    private String sendHttpGet(String url, String user, String password, int returnCodeIDP, int returnCodeRP)
        throws Exception {
        System.out.println(">>>User: " + user + " Password: " + password + " URL: " + url);
        DefaultHttpClient httpclient = new DefaultHttpClient();
        try {
            httpclient.getCredentialsProvider().setCredentials(
                new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
                new UsernamePasswordCredentials(user, password));

            KeyStore trustStore  = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream instream = new FileInputStream(new File("./target/test-classes/server.jks"));
            try {
                trustStore.load(instream, "tompass".toCharArray());
            } finally {
                try {
                    instream.close();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }

            SSLSocketFactory socketFactory = new SSLSocketFactory(trustStore);
            Scheme schIdp = new Scheme("https", Integer.parseInt(getIdpHttpsPort()), socketFactory);
            httpclient.getConnectionManager().getSchemeRegistry().register(schIdp);
            Scheme schRp = new Scheme("https", Integer.parseInt(getRpHttpsPort()), socketFactory);
            httpclient.getConnectionManager().getSchemeRegistry().register(schRp);

            HttpGet httpget = new HttpGet(url);

            HttpResponse response = httpclient.execute(httpget);
            HttpEntity entity = response.getEntity();
            
            System.out.println(response.getStatusLine());
            if (entity != null) {
                System.out.println("Response content length: " + entity.getContentLength());
            }
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

            httpclient.setRedirectStrategy(new LaxRedirectStrategy());
            

            Source source = new Source(EntityUtils.toString(entity));
            List <NameValuePair> nvps = new ArrayList <NameValuePair>();
            FormFields formFields = source.getFormFields();
            System.out.println(formFields.getDebugInfo());
            System.out.println(source.getFormControls().toString());
            
            List<Element> forms = source.getAllElements(HTMLElementName.FORM);
            Assert.assertEquals("Only one form expected but got " + forms.size(), 1, forms.size());
            String postUrl = forms.get(0).getAttributeValue("action");
            
            Assert.assertNotNull("Form field 'wa' not found", formFields.get("wa"));
            Assert.assertNotNull("Form field 'wresult' not found", formFields.get("wresult"));
            for (FormField formField : formFields) {
                nvps.add(new BasicNameValuePair(formField.getName(), formField.getValues().get(0)));
            }
            
            HttpPost httppost = new HttpPost(postUrl);
            httppost.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8));

            response = httpclient.execute(httppost);

            entity = response.getEntity();
            System.out.println(response.getStatusLine());
            Assert.assertTrue("RP HTTP Response code: " + response.getStatusLine().getStatusCode()
                              + " [Expected: " + returnCodeRP + "]",
                              returnCodeRP == response.getStatusLine().getStatusCode());

            if (entity != null) {
                System.out.println("Response content length: " + entity.getContentLength());
            }

            return EntityUtils.toString(entity);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            httpclient.getConnectionManager().shutdown();
        }

    }

}
