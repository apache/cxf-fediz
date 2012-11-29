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

package org.apache.cxf.fediz.jetty;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import net.htmlparser.jericho.FormField;
import net.htmlparser.jericho.FormFields;
import net.htmlparser.jericho.Source;


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


public class BrowserTest {

    private static Server server;

    
    @BeforeClass
    public static void init() {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");

        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");

        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "debug");

        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "debug");
        initIdp();
        initWebApp();
    }
    
    private static void initWebApp() {
        try {
            Resource testServerConfig = Resource.newSystemResource("fedserver.xml");
            XmlConfiguration configuration = new XmlConfiguration(testServerConfig.getInputStream());
            server = (Server)configuration.configure();   
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void initIdp() {
        try {
            Resource testServerConfig = Resource.newSystemResource("idpserver.xml");
            XmlConfiguration configuration = new XmlConfiguration(testServerConfig.getInputStream());
            server = (Server)configuration.configure();
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @org.junit.Test
    public void testStart() throws Exception {
        System.out.println(System.getProperty("jetty.home"));
        System.out.println(Server.getVersion());
        System.out.println(server.isRunning());
    }
    
    //Ignore still IDP/STS is mocked also
    @org.junit.Test
    public void testGetSecureUrl() throws Exception {
        String uri = "http://localhost:8080/fedizhelloworld/secure/fedservlet";
        DefaultHttpClient httpclient = new DefaultHttpClient();
        String user = "alice";
        try {
            httpclient.getCredentialsProvider().setCredentials(
                    new AuthScope("localhost", 9443),
                    new UsernamePasswordCredentials(user, "ecila"));

            KeyStore trustStore  = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream instream = new FileInputStream(new File("./target/test-classes/tomcat-idp.jks"));
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
            Scheme sch = new Scheme("https", 9443, socketFactory);
            httpclient.getConnectionManager().getSchemeRegistry().register(sch);
            
            HttpGet httpget = new HttpGet(uri);

            //System.out.println("executing request " + httpget.getRequestLine());
            HttpResponse response = httpclient.execute(httpget);
            HttpEntity entity = response.getEntity();

            //System.out.println("----------------------------------------");
            //System.out.println(response.getStatusLine());
            //if (entity != null) {
            //    System.out.println("Response content length: " + entity.getContentLength());
            //}
            
//            Redirect to a POST is not supported without user interaction
//            http://www.ietf.org/rfc/rfc2616.txt
//            If the 301 status code is received in response to a request other
//            than GET or HEAD, the user agent MUST NOT automatically redirect the
//            request unless it can be confirmed by the user, since this might
//            change the conditions under which the request was issued.
            
            httpclient.setRedirectStrategy(new LaxRedirectStrategy());
            HttpPost httppost = new HttpPost(uri);
 
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
            //System.out.println("----------------------------------------");
            //System.out.println(response.getStatusLine());
            //if (entity != null) {
            //    System.out.println("Response content length: " + entity.getContentLength());
            //}
            
            String responseContent = EntityUtils.toString(entity);
            
            Assert.assertTrue("Principal not alice", responseContent.indexOf("Principal: " + user) > 0);
            //Has role 'Admin': no<p>
            //Has role 'Manager': no<p>
            //Has role 'User': no<p>
            
        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            httpclient.getConnectionManager().shutdown();
        }
        
    }
    
    
    @AfterClass
    public static void cleanup() {
        if (server.isStarted()) {
            try {
                server.stop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
}
