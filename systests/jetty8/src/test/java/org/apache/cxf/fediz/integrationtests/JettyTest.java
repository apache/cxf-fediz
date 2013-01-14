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




import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.xml.XmlConfiguration;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;


public class JettyTest extends AbstractTests {

    static String idpHttpsPort;
    static String rpHttpsPort;
    
    private static Server idpServer;
    private static Server rpServer;
    
    @BeforeClass
    public static void init() {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");

        System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");

        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "debug");

        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "debug");

        idpHttpsPort = System.getProperty("idp.https.port");
        Assert.assertNotNull("Property 'idp.https.port' null", idpHttpsPort);
        rpHttpsPort = System.getProperty("rp.https.port");
        Assert.assertNotNull("Property 'rp.https.port' null", rpHttpsPort);

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

    @Override
    public String getIdpHttpsPort() {
        return idpHttpsPort;
    }

    @Override
    public String getRpHttpsPort() {
        return rpHttpsPort;
    }
    
    
}
