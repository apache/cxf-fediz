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
import java.io.PrintWriter;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FederationPostFilter extends AbstractAuthFilter {

    private static final String PARAM_TOKEN_STORE_NAME = "token.store.name";

    private static final Logger LOG = LoggerFactory.getLogger(FederationPostFilter.class);
    
//    static {
//        LOG = LoggerFactory.getLogger(FederationPostFilter.class);
//    }
    
    protected String tokenStoreName;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);

        tokenStoreName = filterConfig.getInitParameter(PARAM_TOKEN_STORE_NAME);
        if (tokenStoreName == null) {
            throw new ServletException(
                                       "Parameter '" + PARAM_TOKEN_STORE_NAME + "' not configured");
        }
    }

    @Override
    public void process(HttpServletRequest request,
                        HttpServletResponse response, AuthContext context)
        throws IOException, ServletException, ProcessingException {

        if (context.get(FederationFilter.PARAM_ACTION) == null) {
            LOG.info("Not a WS-Federation request");            
            return;
        }
        
        try {
            Object obj = context.get(tokenStoreName);
            if (!(obj instanceof String)) {
                LOG.error("Token in '" + tokenStoreName + "' not of type String/RSTR");
                throw new IllegalStateException("Token in '" + tokenStoreName + "' not of type String/RSTR");
            }
            request.setAttribute("fed." + FederationFilter.PARAM_WRESULT,
                                 StringEscapeUtils.escapeXml((String)obj));
            String wctx = (String)context.get(FederationFilter.PARAM_WCONTEXT);
            if (wctx != null) {
                request.setAttribute("fed." + FederationFilter.PARAM_WCONTEXT,
                                     StringEscapeUtils.escapeXml(wctx));
            }
            String wreply = (String)context.get(FederationFilter.PARAM_WREPLY);
            String wtrealm = (String)context.get(FederationFilter.PARAM_WTREALM);
            if (wreply == null) {
                request.setAttribute("fed.action", wtrealm);
            } else {
                request.setAttribute("fed.action", wreply);
            }

        } catch (Exception ex) {
            LOG.warn("Requesting security token failed", ex);
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                "Requesting security token failed");
            throw new ProcessingException("Requesting security token failed");          
        }

        setResponseBody(request, response);
        context.put(AbstractAuthFilter.PROCESSING_STATE, AbstractAuthFilter.ProcessingState.SEND_RESPONSE);

    }
    
    private void setResponseBody(HttpServletRequest request, HttpServletResponse response) {
        
        try {
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            
            out.println("<html>");
            out.println("<head><title>IDP SignIn Response Form</title></head>");
            out.println("<body>");
            out.println("<form method=\"POST\" name=\"hiddenform\" action=\"" 
                        + request.getAttribute("fed.action") + "\">");
            out.println("<input type=\"hidden\" name=\"wa\" value=\"wsignin1.0\" />");
            out.println("<input type=\"hidden\" name=\"wresult\" value=\"" 
                        + request.getAttribute("fed.wresult") + "\"/>");
            out.println("<input type=\"hidden\" name=\"wctx\" value=\"" 
                        + request.getAttribute("fed.wctx") + "\"/>");
            out.println("<noscript>");
            out.println("<p>Script is disabled. Click Submit to continue.</p>");
            out.println("<input type=\"submit\" value=\"Submit\" />");
            out.println("</noscript>");
            out.println("</form>");
            out.println("<script language=\"javascript\">window.setTimeout('document.forms[0].submit()',0);</script>");
            out.println("</body>");
            out.println("</html>");
            
        } catch (IOException ex) {
            LOG.error("Failed to create SignInResponse message", ex);
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                                   "Failed to create SignInResponse message");
            } catch (IOException e) {
                LOG.error("Failed to write error reponse", e);
            }
        }
        
    }
}

