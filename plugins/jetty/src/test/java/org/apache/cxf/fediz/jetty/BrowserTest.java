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


import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.xml.XmlConfiguration;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;


public class BrowserTest {

    private static Server server;

    
    @BeforeClass
    public static void init() {        
        try {
            //Resource testServerConfig = Resource.newSystemResource("testserver.xml");
            Resource testServerConfig = Resource.newSystemResource("fedserver.xml");
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
    @Ignore
    public void testGetSecureUrl() throws Exception {
        String uri = "http://localhost:8080/fedizhelloworld/secure/fedservlet";
        DefaultHttpClient httpclient = new DefaultHttpClient();
        try {
            httpclient.getCredentialsProvider().setCredentials(
                    new AuthScope("localhost", 9443),
                    new UsernamePasswordCredentials("alice", "ecila"));

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

            System.out.println("executing request" + httpget.getRequestLine());
            HttpResponse response = httpclient.execute(httpget);
            HttpEntity entity = response.getEntity();

            System.out.println("----------------------------------------");
            System.out.println(response.getStatusLine());
            if (entity != null) {
                System.out.println("Response content length: " + entity.getContentLength());
            }
            EntityUtils.consume(entity);
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
