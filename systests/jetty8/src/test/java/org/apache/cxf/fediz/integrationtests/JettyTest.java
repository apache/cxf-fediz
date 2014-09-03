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
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;


public class JettyTest extends AbstractTests {

    static String idpHttpsPort;
    static String rpHttpsPort;
    
    @BeforeClass
    public static void init() {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.webflow", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security.web", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf.fediz", "info");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf", "info");

        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

        JettyUtils.initIdpServer();
        JettyUtils.startIdpServer();
        JettyUtils.initRpServer();
        JettyUtils.startRpServer();
    }
    
    @AfterClass
    public static void cleanup() {
        JettyUtils.stopIdpServer();
        JettyUtils.stopRpServer();
    }

    @Override
    public String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    @Override
    public String getRpHttpsPort() {
        return rpHttpsPort;
    }
    
    @Override
    public String getServletContextName() {
        return "fedizhelloworld";
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
    
}
