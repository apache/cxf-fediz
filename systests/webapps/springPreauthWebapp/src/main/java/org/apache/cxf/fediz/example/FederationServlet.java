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
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

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
        out.println("<p>Request url: "); out.println(request.getRequestURL()); out.println("</p>");

        out.print("<p>userPrincipal=");
        Principal p = request.getUserPrincipal();
        if (p != null) {
            out.print(p.getName());
        }
        out.println("</p>");

        List<String> roleListToCheck = Arrays.asList("Admin", "Manager", "User", "Authenticated");
        for (String item : roleListToCheck) {
            out.println("<p>role:" + item + "=" + ((request.isUserInRole(item)) ? "true" : "false") + "</p>");
        }

        if (p instanceof FedizPrincipal) {
            FedizPrincipal fp = (FedizPrincipal)p;

            ClaimCollection claims = fp.getClaims();
            for (Claim c : claims) {
                out.println("<p>" + c.getClaimType().toString() + "=" + c.getValue() + "</p>");
            }

            Element el = fp.getLoginToken();
            if (el != null) {
                out.println("loginToken=FOUND{FedizPrincipal}<p>");
            }

            el = SecurityTokenThreadLocal.getToken();
            if (el != null) {
                out.println("loginToken=FOUND{SecurityTokenThreadLocal}<p>");
            }
        }

        out.println("</body>");

        // Access Spring security context
        Assert.notNull(SecurityContextHolder.getContext().getAuthentication(),
                       "SecurityContextHolder Authentication not null");

        Authentication obj = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("getCredentials: " + obj.getCredentials().toString());
        System.out.println("getDetails: " + obj.getDetails().toString());
        System.out.println("getName: " + obj.getName());
        System.out.println("getAuthorities: " + obj.getAuthorities().toString());
        System.out.println("getPrincipal: " + obj.getPrincipal().toString());

    }

}
