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
        System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "debug");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "debug");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.webflow", "debug");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security.web", "debug");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.springframework.security", "debug");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf.fediz", "debug");
        System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.cxf", "debug"); 

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
    
}
