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

package org.apache.cxf.fediz.example;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationToken;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.context.SecurityContextHolder;

public class FederationServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = -9019993850246851112L;

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
        IOException {

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        out.println("<html>");
        out.println("<head><title>WS Federation Systests Spring Examples</title></head>");
        out.println("<body>");
        out.println("<p>Request url: " + request.getRequestURL().toString() + "</p>");

        out.print("<p>userPrincipal=");
        Principal p = request.getUserPrincipal();
        if (p != null) {
            out.print(p.getName());
        }
        out.println("</p>");

        // Access Spring security context
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (auth instanceof FederationAuthenticationToken) {
            FederationAuthenticationToken fedToken = (FederationAuthenticationToken)auth;
            List<String> roleListToCheck = Arrays.asList("Admin", "Manager", "User", "Authenticated");
            
            for (String item : roleListToCheck) {
                boolean found = false;
                for (GrantedAuthority ga : fedToken.getAuthorities()) {
                    if (ga.getAuthority().toLowerCase().indexOf(item.toLowerCase()) > -1) {
                        found = true;
                        break;
                    }
                }
                out.println("<p>role:" + item + "=" + (found ? "true" : "false") + "</p>");
            }
            
            ClaimCollection claims = fedToken.getClaims();
            for (Claim c : claims) {
                out.println("<p>" + c.getClaimType().toString() + "=" + c.getValue() + "</p>");
            }
            
            Element el = fedToken.getLoginToken();
            if (el != null) {
                out.println("loginToken=FOUND{FedizPrincipal}<p>");
            }
            
            el = SecurityTokenThreadLocal.getToken();
            if (el != null) {
                out.println("loginToken=FOUND{SecurityTokenThreadLocal}<p>");
            }
            
        }
                
        out.println("</body>");
        
    }

}
