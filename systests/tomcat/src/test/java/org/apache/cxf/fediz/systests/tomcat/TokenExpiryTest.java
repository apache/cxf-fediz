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

package org.apache.cxf.fediz.systests.tomcat;


import org.apache.cxf.fediz.systests.common.AbstractExpiryTests;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * Some token expiry tests
 */
public class TokenExpiryTest extends AbstractExpiryTests {

    private static final String SERVLET_CONTEXT_NAME = "fedizhelloworld_wfresh";

    @BeforeClass
    public static void init() throws Exception {
        TomcatLauncher.startServer(SERVLET_CONTEXT_NAME);
    }

    @AfterClass
    public static void cleanup() throws Exception {
        TomcatLauncher.shutdownServer();
    }

    public String getIdpHttpsPort() {
        return TomcatLauncher.getIdpHttpsPort();
    }

    public String getRpHttpsPort() {
        return TomcatLauncher.getRpHttpsPort();
    }

    @Override
    public String getServletContextName() {
        return SERVLET_CONTEXT_NAME;
    }

}
