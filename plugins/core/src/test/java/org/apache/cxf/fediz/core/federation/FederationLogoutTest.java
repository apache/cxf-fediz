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

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.cxf.fediz.common.SecurityTestUtil;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.handler.LogoutHandler;
import org.easymock.EasyMock;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

/**
 * Some tests for logout for WS-Federation
 */
public class FederationLogoutTest {
    private static final String LOGOUT_URL = "https://localhost/fedizhelloworld/secure/logout";
    private static final String LOGOUT_URI = "/secure/logout";
    private static final String REPLY_URI = "/wreply.html";
    private static final String REPLY_URL = "https://localhost/fedizhelloworld/secure/wreply.html";
    private static final String BAD_REPLY_URL = "https://localhost/fedizhelloworld/secure/badreply.html";
    
    private static final String CONFIG_FILE = "fediz_test_config_logout.xml";
    
    private static FedizConfigurator configurator;
    private static DocumentBuilderFactory docBuilderFactory;
    
    static {
        docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true);
    }
    
    
    @BeforeClass
    public static void init() {
        getFederationConfigurator();
        Assert.assertNotNull(configurator);
    }
    
    @AfterClass
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
    
    @org.junit.Test
    public void testSignoutCustomURL() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION)).andReturn(null).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=https%3A%2F%2Flocalhost%2Fsecure%2Flogout%2Findex.html"
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutCustomURLWithWReply() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION)).andReturn(null).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(REPLY_URL).anyTimes();
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=" + URLEncoder.encode(REPLY_URL, "UTF-8")
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutCustomURLWithBadWReply() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION)).andReturn(null).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(BAD_REPLY_URL).anyTimes();
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=https%3A%2F%2Flocalhost%2Fsecure%2Flogout%2Findex.html"
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }

    @org.junit.Test
    public void testSignoutCustomURLWithNoConfiguredConstraint() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT2");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION)).andReturn(null).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(REPLY_URI).anyTimes();
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=https%3A%2F%2Flocalhost%2Fsecure%2Flogout%2Findex.html"
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutWithAbsoluteURL() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT4");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION)).andReturn(null).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer(LOGOUT_URL));
        EasyMock.expect(req.getRequestURI()).andReturn(LOGOUT_URI);
        EasyMock.expect(req.getContextPath()).andReturn(LOGOUT_URI);
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=https%3A%2F%2Flocalhost%2Fsecure%2Flogout%2Findex.html"
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutAction() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNOUT).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(null);
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer("https://localhost/fedizhelloworld/secure"));
        EasyMock.expect(req.getRequestURI()).andReturn("/secure");
        EasyMock.expect(req.getContextPath()).andReturn("/secure");
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=https%3A%2F%2Flocalhost%2Fsecure%2Findex.html"
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutActionWithWReply() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNOUT).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(REPLY_URL).anyTimes();
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer("https://localhost/fedizhelloworld/secure"));
        EasyMock.expect(req.getRequestURI()).andReturn("/secure");
        EasyMock.expect(req.getContextPath()).andReturn("/secure");
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=" + URLEncoder.encode(REPLY_URL, "UTF-8")
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutActionWithBadWReply() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNOUT).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(BAD_REPLY_URL).anyTimes();
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer("https://localhost/fedizhelloworld/secure"));
        EasyMock.expect(req.getRequestURI()).andReturn("/secure");
        EasyMock.expect(req.getContextPath()).andReturn("/secure");
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=https%3A%2F%2Flocalhost%2Fsecure%2Findex.html"
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutActionWithNoConfiguredConstraint() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT2");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
        .andReturn(FederationConstants.ACTION_SIGNOUT).anyTimes();
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(REPLY_URL).anyTimes();
        EasyMock.expect(req.getRequestURL()).andReturn(new StringBuffer("https://localhost/fedizhelloworld/secure"));
        EasyMock.expect(req.getRequestURI()).andReturn("/secure");
        EasyMock.expect(req.getContextPath()).andReturn("/secure");
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirectToIdP =
            "http://url_to_the_issuer?wa=wsignout1.0&wreply=https%3A%2F%2Flocalhost%2Fsecure%2Findex.html"
            + "&wtrealm=target+realm";
        resp.sendRedirect(expectedRedirectToIdP);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutCleanupWithWReply() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        HttpSession session =  EasyMock.createMock(HttpSession.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNOUT_CLEANUP).anyTimes();
        EasyMock.expect(req.getSession()).andReturn(session);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(REPLY_URL).anyTimes();
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        String expectedRedirect = URLEncoder.encode(REPLY_URL, "UTF-8");
        resp.sendRedirect(expectedRedirect);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutCleanupWithBadWReply() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        HttpSession session =  EasyMock.createMock(HttpSession.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNOUT_CLEANUP).anyTimes();
        EasyMock.expect(req.getSession()).andReturn(session);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(BAD_REPLY_URL).anyTimes();
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        resp.setContentType("image/jpeg");
        ServletOutputStream outputStream = EasyMock.createMock(ServletOutputStream.class);
        EasyMock.expect(resp.getOutputStream()).andReturn(outputStream);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
    
    @org.junit.Test
    public void testSignoutCleanupWithNoConfiguredConstraint() throws Exception {
        FedizContext config = getFederationConfigurator().getFedizContext("ROOT2");
        
        HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
        HttpSession session =  EasyMock.createMock(HttpSession.class);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_ACTION))
            .andReturn(FederationConstants.ACTION_SIGNOUT_CLEANUP).anyTimes();
        EasyMock.expect(req.getSession()).andReturn(session);
        EasyMock.expect(req.getParameter(FederationConstants.PARAM_REPLY)).andReturn(REPLY_URL).anyTimes();
        EasyMock.replay(req);
        
        LogoutHandler logoutHandler = new LogoutHandler(config);
        Assert.assertTrue(logoutHandler.canHandleRequest(req));
        
        HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
        resp.setContentType("image/jpeg");
        ServletOutputStream outputStream = EasyMock.createMock(ServletOutputStream.class);
        EasyMock.expect(resp.getOutputStream()).andReturn(outputStream);
        EasyMock.expectLastCall();
        EasyMock.replay(resp);
        logoutHandler.handleRequest(req, resp);
    }
}
