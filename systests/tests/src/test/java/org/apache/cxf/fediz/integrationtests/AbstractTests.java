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

import javax.net.ssl.SSLContext;

import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.util.EntityUtils;
import org.junit.Assert;

public abstract class AbstractTests {

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
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

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
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          response.indexOf(claim + "=alice@realma.org") > 0);

    }
    
    @org.junit.Test
    public void testAliceUser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "alice";
        String password = "ecila";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=false") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=false") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);
    }
    
    @org.junit.Test
    public void testAliceAdminNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "alice";
        String password = "ecila";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));        
    }
    
    @org.junit.Test
    public void testAliceManagerNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "alice";
        String password = "ecila";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));        
    }

    @org.junit.Test
    public void testAliceWrongPasswordNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "alice";
        // sendHttpGet(url, user, password, 500, 0);        
        //[FIXED] Fix IDP return code from 500 to 401
        HTTPTestUtils.sendHttpGet(url, user, password, 401, 0, Integer.parseInt(getIdpHttpsPort()));        
    }

    @org.junit.Test
    public void testBob() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

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
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'bobwindsor@realma.org'",
                          response.indexOf(claim + "=bobwindsor@realma.org") > 0);
    }
    
    @org.junit.Test
    public void testBobUser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=true") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=true") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);
    }
    
    @org.junit.Test
    public void testBobManager() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=true") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=true") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);
    }
    
    @org.junit.Test
    public void testBobAdmin() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=true") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=true") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);
    }

    @org.junit.Test
    public void testTed() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "ted";
        String password = "det";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

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
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'tcooper@realma.org'",
                          response.indexOf(claim + "=tcooper@realma.org") > 0);
    }
    
    @org.junit.Test
    public void testTedUserNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "ted";
        String password = "det";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));
    }

    @org.junit.Test
    public void testTedAdminNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "ted";
        String password = "det";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));        
    }
    
    @org.junit.Test
    public void testTedManagerNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "ted";
        String password = "det";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));        
    }

    @org.junit.Test
    public void testMetadata() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() 
            + "/fedizhelloworld/FederationMetadata/2007-06/FederationMetadata.xml";

        CloseableHttpClient httpClient = null;
        try {
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
            httpClientBuilder.setSSLSocketFactory(sslSocketFactory);
            httpClientBuilder.setRedirectStrategy(new LaxRedirectStrategy());

            httpClient = httpClientBuilder.build();

            HttpGet httpget = new HttpGet(url);

            HttpResponse response = httpClient.execute(httpget);
            HttpEntity entity = response.getEntity();

            Assert.assertEquals(200, response.getStatusLine().getStatusCode());

            String metadata = EntityUtils.toString(entity);
            Assert.assertTrue(metadata.startsWith("<EntityDescriptor"));
        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            if (httpClient != null) {
                httpClient.close();
            }
        }
    }
    
    @org.junit.Test
    public void testAliceLogout() throws Exception {
        // Authenticate as "alice"
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "ecila";
        
        CloseableHttpClient httpClient = 
            HTTPTestUtils.sendHttpGetForSignIn(url, user, password, 200, 200, Integer.parseInt(getIdpHttpsPort()));
        
        String logoutUrl = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/logout";
        String logoutResponse = 
            HTTPTestUtils.sendHttpGetForSignOut(httpClient, logoutUrl, 200, 200, Integer.parseInt(getIdpHttpsPort()));
        
        Assert.assertTrue(logoutResponse.contains("IDP SignOut Response Page"));
        Assert.assertTrue(logoutResponse.contains("Logout status of RP"));
        Assert.assertTrue(logoutResponse.contains("wsignoutcleanup1.0"));
    }
    
}
