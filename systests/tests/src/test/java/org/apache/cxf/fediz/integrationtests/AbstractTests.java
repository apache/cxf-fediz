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

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.xml.XmlPage;

import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FederationConstants;
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
    public void testMetadata() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() 
            + "/fedizhelloworld/FederationMetadata/2007-06/FederationMetadata.xml";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getOptions().setSSLClientCertificate(
            this.getClass().getClassLoader().getResource("client.jks"), "clientpass", "jks");

        final XmlPage rpPage = webClient.getPage(url);
        final String xmlContent = rpPage.asXml();
        Assert.assertTrue(xmlContent.startsWith("<EntityDescriptor"));
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
}
