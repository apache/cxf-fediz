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
import java.io.StringWriter;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.apache.hello_world_soap_http.Greeter;
import org.springframework.web.util.HtmlUtils;


public class FederationServlet extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = -9019993850246851112L;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        out.println("<html>");
        out.println("<head><title>WS Federation Tomcat Examples</title></head>");
        out.println("<body>");
        out.println("<h1>Hello World</h1>");
        out.println("Hello world<br>");
        out.println("Request url: "); out.println(request.getRequestURL()); out.println("<p>");


        out.println("<br><b>User</b><p>");
        Principal p = request.getUserPrincipal();
        if (p != null) {
            out.println("Principal: " + p.getName() + "<p>");
        }

        out.println("<br><b>Roles</b><p>");
        List<String> roleListToCheck = Arrays.asList("Admin", "Manager", "User", "Authenticated");
        for (String item: roleListToCheck) {
            out.println("Has role '" + item + "': " + ((request.isUserInRole(item)) ? "<b>yes</b>" : "no") + "<p>");
        }

        if (p instanceof FedizPrincipal) {
            FedizPrincipal fp = (FedizPrincipal)p;

            out.println("<br><b>Claims</b><p>");
            ClaimCollection claims = fp.getClaims();
            for (Claim c: claims) {
                out.println(c.getClaimType().toString() + ": " + c.getValue() + "<p>");
            }
        } else {
            out.println("Principal is not instance of FedizPrincipal");
        }

        Element el = SecurityTokenThreadLocal.getToken();
        if (el != null) {
            out.println("<p>Bootstrap token...");
            String token = null;
            try {
                TransformerFactory transFactory = TransformerFactory.newInstance();
                Transformer transformer = transFactory.newTransformer();
                StringWriter buffer = new StringWriter();
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                transformer.transform(new DOMSource(el),
                                      new StreamResult(buffer));
                token = buffer.toString();
                out.println("<p>" + HtmlUtils.htmlEscape(token));
            } catch (Exception ex) {
                out.println("<p>Failed to transform cached element to string: " + ex.toString());
            }
        } else {
            out.println("<p>Bootstrap token not cached in thread local storage");
        }

        out.println("</body>");
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        out.println("<html>");
        out.println("<head><title>WS Federation Tomcat Examples</title></head>");
        out.println("<body>");
        out.println("<h1>Hello World</h1>");
        out.println("Hello world<br>");
        out.println("Request url: " + request.getRequestURL().toString() + "<p>");



        out.println("<br><b>User</b><p>");
        Principal p = request.getUserPrincipal();
        if (p != null) {
            out.println("Principal: " + p.getName() + "<p>");
        }

        out.println("<br><b>Roles</b><p>");
        List<String> roleListToCheck = Arrays.asList("Admin", "Manager", "User", "Authenticated");
        for (String item: roleListToCheck) {
            out.println("Has role '" + item + "': " + ((request.isUserInRole(item)) ? "<b>yes</b>" : "no") + "<p>");
        }

        if (p instanceof FedizPrincipal) {
            FedizPrincipal fp = (FedizPrincipal)p;

            out.println("<br><b>Claims</b><p>");
            ClaimCollection claims = fp.getClaims();
            for (Claim c: claims) {
                out.println(c.getClaimType().toString() + ": " + c.getValue() + "<p>");
            }
        } else {
            out.println("Principal is not instance of FedizPrincipalImpl");
        }

        Greeter service = (Greeter)ApplicationContextProvider.getContext().getBean("HelloServiceClient");
        String reply = service.greetMe();

        out.println("<br><b>Greeter Service Response: " + reply + "</b><p>");

        out.println("</body>");
    }

}
