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

package org.apache.cxf.fediz.cxf.web;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Element;

/**
 * Add security token to thread local
 */
public class FederationFilter implements Filter {

    private static final String DEFAULT_SECURITY_TOKEN_ATTR = "org.apache.fediz.SECURITY_TOKEN";
    private static final String SECURITY_TOKEN_ATTR_CONFIG = "security.token.attribute";

    private String securityTokenAttr = DEFAULT_SECURITY_TOKEN_ATTR;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String attrName = filterConfig.getInitParameter(SECURITY_TOKEN_ATTR_CONFIG);
        if (attrName != null) {
            securityTokenAttr = attrName;
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {
            HttpServletRequest hrequest = (HttpServletRequest)request;
            Element el = (Element)hrequest.getSession().getAttribute(securityTokenAttr);
            if (el != null) {
                try {
                    SecurityTokenThreadLocal.setToken(el);
                    chain.doFilter(request, response);
                } finally {
                    SecurityTokenThreadLocal.setToken(null);
                }
            } else {
                chain.doFilter(request, response);
            }

        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {
    }

}
