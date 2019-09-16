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

package org.apache.cxf.fediz.systests.jetty9;

import org.apache.cxf.fediz.systests.common.AbstractClientCertTests;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * In this test-case, the IdP is set up to require client authentication, rather than authenticating using a
 * username + password, or via Kerberos.
 */
public class ClientCertificatePreAuthSpringTest extends AbstractClientCertTests {

    private static final String RP_HTTPS_PORT = System.getProperty("rp.https.port");

    @BeforeClass
    public static void init() throws Exception {
        Assert.assertNotNull("Property 'rp.jetty.https.port' null", RP_HTTPS_PORT);
        TomcatUtils.initIdpServer();
        JettyUtils.initRpServer("rp-client-cert-server.xml");
    }

    @AfterClass
    public static void cleanup() throws Exception {
        TomcatUtils.stopIdpServer();
        JettyUtils.stopRpServer();
    }

    @Override
    public String getIdpHttpsPort() {
        return TomcatUtils.getIdpHttpsPort();
    }

    @Override
    public String getRpHttpsPort() {
        return RP_HTTPS_PORT;
    }

    @Override
    public String getServletContextName() {
        return "fedizspringhelloworld";
    }

}
