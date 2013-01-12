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

import net.htmlparser.jericho.FormField;
import net.htmlparser.jericho.FormFields;
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
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.xml.XmlConfiguration;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;


public class JettyTest {

    private static String idpHttpsPort;
    private static String rpHttpsPort;
    
    private static Server idpServer;
    private static Server rpServer;
    
    @BeforeClass
    public static void init() {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");

        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");

        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "debug");

        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "debug");

        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull(idpHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull(rpHttpsPort);

        initIdp();
        Assert.assertTrue("IDP server not running", idpServer.isRunning());
        initRp();
        Assert.assertTrue("RP server not running", rpServer.isRunning());
    }
    
    private static void initIdp() {
        try {
            Resource testServerConfig = Resource.newSystemResource("jetty/rp-server.xml");
            XmlConfiguration configuration = new XmlConfiguration(testServerConfig.getInputStream());
            idpServer = (Server)configuration.configure();   
            idpServer.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void initRp() {
        try {
            Resource testServerConfig = Resource.newSystemResource("jetty/idp-server.xml");
            XmlConfiguration configuration = new XmlConfiguration(testServerConfig.getInputStream());
            rpServer = (Server)configuration.configure();
            rpServer.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /*
    @org.junit.Test
    @Ignore
    public void testStart() throws Exception {
        System.out.println(System.getProperty("jetty.home"));
        System.out.println(Server.getVersion());
        System.out.println(server.isRunning());
    }
    */

    @org.junit.Test
    public void testUserAlice() throws Exception {
        String url = "https://localhost:" + rpHttpsPort + "/fedizhelloworld/secure/fedservlet";
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
        
    }
    
    @org.junit.Test
    public void testUserBob() throws Exception {
        String url = "https://localhost:" + rpHttpsPort + "/fedizhelloworld/secure/fedservlet";
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
    }
    
    @org.junit.Test
    public void testUserTed() throws Exception {
        String url = "https://localhost:" + rpHttpsPort + "/fedizhelloworld/secure/fedservlet";
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
    }
    
    @org.junit.Test
    public void testUserAliceNoAccess() throws Exception {
        String url = "https://localhost:" + rpHttpsPort + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "alice";
        String password = "ecila";
        sendHttpGet(url, user, password, 200, 403);        
    }
    
    @org.junit.Ignore
    @org.junit.Test
    public void testUserAliceWrongPassword() throws Exception {
        String url = "https://localhost:" + rpHttpsPort + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "alice";
        //[TODO] Fix IDP return code from 500 to 401
        sendHttpGet(url, user, password, 500, 0);        
    }
    
    @org.junit.Test
    public void testUserTedNoAccess() throws Exception {
        String url = "https://localhost:" + rpHttpsPort + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "ted";
        String password = "det";
        sendHttpGet(url, user, password, 200, 403);        
    }
    
    private String sendHttpGet(String url, String user, String password) throws Exception {
        return sendHttpGet(url, user, password, 200, 200);
    }
    
    private String sendHttpGet(String url, String user, String password, 
                               int returnCodeIDP, int returnCodeRP) throws Exception {
        DefaultHttpClient httpclient = new DefaultHttpClient();
        try {
            httpclient.getCredentialsProvider().setCredentials(
                    new AuthScope("localhost", Integer.parseInt(idpHttpsPort)),
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
            Scheme schIdp = new Scheme("https", Integer.parseInt(idpHttpsPort), socketFactory);
            httpclient.getConnectionManager().getSchemeRegistry().register(schIdp);
            Scheme schRp = new Scheme("https", Integer.parseInt(rpHttpsPort), socketFactory);
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
            HttpPost httppost = new HttpPost(url);
 
            Source source = new Source(EntityUtils.toString(entity));
            List <NameValuePair> nvps = new ArrayList <NameValuePair>();
            FormFields formFields = source.getFormFields();
            Assert.assertNotNull("Form field 'wa' not found", formFields.get("wa"));
            Assert.assertNotNull("Form field 'wresult' not found", formFields.get("wresult"));
            for (FormField formField : formFields) {
                nvps.add(new BasicNameValuePair(formField.getName(), formField.getValues().get(0)));
            }
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
        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            httpclient.getConnectionManager().shutdown();
        }
        
    }
    
    
    @AfterClass
    public static void cleanup() {
        if (idpServer != null && idpServer.isStarted()) {
            try {
                idpServer.stop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (rpServer != null && rpServer.isStarted()) {
            try {
                rpServer.stop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    
}
