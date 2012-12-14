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
package org.apache.cxf.fediz.service.idp;

import java.io.IOException;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpFormAuthenticationFilter extends AbstractAuthFilter {

    public static final String PARAM_TAG = "cxf.fediz.loginform.tag";
    public static final String PARAM_USERNAME = "cxf.fediz.loginform.username";
    public static final String PARAM_PASSWORD = "cxf.fediz.loginform.password";
    public static final String FORM_LOGIN_PAGE_URI_DEFAULT = "/WEB-INF/signinform.jsp";

    private static final Logger LOG = LoggerFactory.getLogger(HttpFormAuthenticationFilter.class);
    
    private static final String PARAM_FORM_LOGIN_PAGE = "form.login.page";
    
    protected String formLoginPage;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        formLoginPage = filterConfig.getInitParameter(PARAM_FORM_LOGIN_PAGE);
        if (formLoginPage != null && formLoginPage.length() > 0) {
            LOG.info("Configured form login page: " + formLoginPage);
        }
    }
    
    @Override
    public void process(HttpServletRequest request,
                        HttpServletResponse response, AuthContext context)
        throws IOException, ServletException {

        String tag = request.getParameter(PARAM_TAG);

        if (tag == null) {
            // request authentication from user
            response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
            
            if (formLoginPage != null && formLoginPage.length() > 0) {
                request.getRequestDispatcher(formLoginPage)
                    .forward(request, response);
            } else {
                request.getRequestDispatcher(FORM_LOGIN_PAGE_URI_DEFAULT)
                    .forward(request, response);
            }
            
            setNextState(States.USERNAME_PASSWORD_REQUIRED.toString(), context);
            context.put(AbstractAuthFilter.PROCESSING_STATE,
                        AbstractAuthFilter.ProcessingState.SEND_RESPONSE);
            return;

        } else {
            String username = request.getParameter(PARAM_USERNAME);
            String password = request.getParameter(PARAM_PASSWORD);

            try {
                context.put(AuthContext.AUTH_USERNAME, username);
                context.put(AuthContext.AUTH_PASSWORD, password);
            } catch (Exception ex) {
                LOG.error("Invalid Authorization header", ex);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid http form format");
                throw new ProcessingException("Invalid http form format");
            }
        }
    }

}
