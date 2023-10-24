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

package org.apache.cxf.fediz.core.federation;

import java.io.File;
import java.net.URL;
import java.net.URLEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.processor.FederationProcessorImpl;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.RedirectionResponse;

import org.easymock.EasyMock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;

/**
 * Some tests for creating WS-Federation requests using the FederationProcessorImpl
 */
public class FederationRequestTest {
    static final String TEST_USER = "alice";
    static final String TEST_RSTR_ISSUER = "FedizSTSIssuer";
    static final String TEST_REQUEST_URL = "https://localhost/fedizhelloworld/";
    static final String TEST_REQUEST_URI = "/fedizhelloworld";
    static final String TEST_IDP_ISSUER = "http://url_to_the_issuer";

    private static final String CONFIG_FILE = "fediz_test_config.xml";

    private static FedizConfigurator configurator;
    private static DocumentBuilderFactory docBuilderFactory;

    static {
        docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true);
    }


    @BeforeAll
    public static void init() {
        getFederationConfigurator();
        Assertions.assertNotNull(configurator);
    }

    @AfterAll
    public static void cleanup() {
        SecurityTestUtil.cleanup();
    }


    private static FedizConfigurator getFederationConfigurator() {
        if (configurator != null) {
            return configurator;
        }
        try {
            configurator = new FedizConfigurator();
            final URL resource = Thread.currentThread().getContextClassLoader()
                    .getResource(CONFIG_FILE);
            File f = new File(resource.toURI());
            configurator.loadConfig(f);
            return configurator;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @org.junit.jupiter.api.Test
    public void createFederationSignInRequest() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_HOME_REALM)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL)).times(1, 2);
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.expect(req.getQueryString()).andReturn(null);
        EasyMock.replay(req);

        FedizProcessor wfProc = new FederationProcessorImpl();
        RedirectionResponse response = wfProc.createSignInRequest(req, config);

        String redirectionURL = response.getRedirectionURL();
        Assertions.assertTrue(redirectionURL.startsWith(TEST_IDP_ISSUER));
        Assertions.assertTrue(redirectionURL.contains("wa=wsignin1.0"));
        Assertions.assertTrue(redirectionURL.contains("wreq=REQUEST"));
        Assertions.assertTrue(redirectionURL.contains("wfresh=10000"));
        Assertions.assertTrue(redirectionURL.contains("wct="));
        Assertions.assertTrue(redirectionURL.contains("wtrealm=target+realm"));
        Assertions.assertTrue(redirectionURL.contains("wreply="));
    }

    @org.junit.jupiter.api.Test
    public void createFederationSignInRequestWithUrlDefinedHomeRealm() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_HOME_REALM))
            .andReturn("urn:org:apache:cxf:fediz:idp:realm-A");
        EasyMock.expect(req.getQueryString()).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL)).times(1, 2);
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.replay(req);

        FedizProcessor wfProc = new FederationProcessorImpl();
        RedirectionResponse response = wfProc.createSignInRequest(req, config);

        String redirectionURL = response.getRedirectionURL();
        Assertions.assertTrue(redirectionURL.startsWith(TEST_IDP_ISSUER));
        Assertions.assertTrue(redirectionURL.contains("wa=wsignin1.0"));
        Assertions.assertTrue(redirectionURL.contains("wreq=REQUEST"));
        Assertions.assertTrue(redirectionURL.contains("wfresh=10000"));
        Assertions.assertTrue(redirectionURL.contains("wct="));
        Assertions.assertTrue(redirectionURL.contains("wtrealm=target+realm"));
        Assertions.assertTrue(redirectionURL.contains("wreply="));
        Assertions.assertTrue(redirectionURL.contains("whr="
                                                + URLEncoder.encode("urn:org:apache:cxf:fediz:idp:realm-A", "UTF-8")));
    }

    @org.junit.jupiter.api.Test
    public void createFederationSignOutRequest() throws Exception {
        // Mock up a Request
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");

        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(TEST_REQUEST_URL)).times(1, 2);
        EasyMock.expect(req.getContextPath()).andReturn(TEST_REQUEST_URI);
        EasyMock.replay(req);

        FedizProcessor wfProc = new FederationProcessorImpl();
        RedirectionResponse response = wfProc.createSignOutRequest(req, null, config);

        String redirectionURL = response.getRedirectionURL();
        Assertions.assertTrue(redirectionURL.startsWith(TEST_IDP_ISSUER));
        Assertions.assertTrue(redirectionURL.contains("wa=wsignout1.0"));
    }

}