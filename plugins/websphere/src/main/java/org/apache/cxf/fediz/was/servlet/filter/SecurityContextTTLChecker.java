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
package org.apache.cxf.fediz.was.servlet.filter;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.Subject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Element;

import com.ibm.websphere.security.WSSecurityException;
import com.ibm.websphere.security.auth.WSSubject;

import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.was.Constants;
import org.apache.cxf.fediz.was.tai.FedizInterceptor;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * A Servlet Filter that MUST be configured to match the '/*' request scheme on each Web Application
 * to enforce SAML assertion TimeToLive checking
 *
 * Only needed if TAI Interceptor is not registered with option "beforeSSO=true". Otherwise use FederationFilter
 * instead.
 */
public class SecurityContextTTLChecker extends HttpServlet implements Filter {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityContextTTLChecker.class);
    private static final long serialVersionUID = 5732969339258858728L;

    private String contextPath;

    /*
     * (non-Java-doc)
     * @see java.lang.Object#Object()
     */
    public SecurityContextTTLChecker() {
        super();
    }

    @SuppressWarnings("deprecation")
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        contextPath = config.getServletContext().getContextPath();
        FedizInterceptor.registerContext(contextPath);
    }

    /*
     * (non-Java-doc)
     * @see javax.servlet.Filter#doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        try {
            FedizResponse fedResponse = null;
            Subject subject = WSSubject.getCallerSubject();
            boolean validSecurityTokenFound = false;
            if (subject != null) {
                fedResponse = getCachedFederationResponse(subject);
                validSecurityTokenFound = checkSecurityToken(fedResponse);
            }
            if (!validSecurityTokenFound) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("Security token not found or WS-Federation session has expired");
                }
                // delete the session
                if (request instanceof HttpServletRequest) {
                    HttpServletRequest req = (HttpServletRequest)request;
                    req.getSession().invalidate();
                }
            } else {
                Element el = (Element)fedResponse.getToken();
                if (el != null) {
                    SecurityTokenThreadLocal.setToken(el);
                }
                LOG.debug("Security token is still valid. Forwarding request");
            }
            chain.doFilter(request, response);
        } catch (WSSecurityException e) {
            throw new ServletException("Unable to get a valid Subject instance in Filter chain context", e);
        } catch (Exception e) {
            LOG.error("Failed validating cached security token", e);
            throw new ServletException("Failed validating cached security token", e);
        } finally {
            SecurityTokenThreadLocal.setToken(null);
        }
    }

    private boolean checkSecurityToken(FedizResponse response) {
        if (response == null) {
            return false;
        }
        long currentTime = System.currentTimeMillis();
        return response.getTokenExpires().getTime() > currentTime;
    }

    private FedizResponse getCachedFederationResponse(Subject subject) {
        Iterator<?> i = subject.getPublicCredentials().iterator();

        while (i.hasNext()) {
            Object o = i.next();
            if (o instanceof Hashtable) {
                @SuppressWarnings("unchecked")
                Map<Object, Object> table = (Hashtable<Object, Object>)o;
                return (FedizResponse)table.get(Constants.SUBJECT_TOKEN_KEY);
            }
        }
        return null;
    }


    /*
     * (non-Java-doc)
     * @see javax.servlet.Filter#destroy()
     */
    @SuppressWarnings("deprecation")
    public void destroy() {
        FedizInterceptor.deRegisterContext(contextPath);
    }

    @SuppressWarnings("deprecation")
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        contextPath = filterConfig.getServletContext().getContextPath();
        FedizInterceptor.registerContext(contextPath);
    }

}
