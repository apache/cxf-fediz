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

import java.io.StringWriter;
import java.security.Principal;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Element;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.apache.cxf.fediz.spring.FederationUser;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;



@Path("/")
public class FederationService {

    @GET
    public Response get(@Context UriInfo uriInfo,
                        @Context SecurityContext securityContext) {

        ResponseBuilder rb = Response.ok().type("text/html");

        StringBuilder out = new StringBuilder(275);
        out.append("<html>");
        out.append("<head><title>WS Federation Spring Security Example</title></head>");
        out.append("<body>");
        out.append("<h1>Hello World</h1>");
        out.append("Hello world<br>");
        out.append("Request url: ").append(uriInfo.getAbsolutePath()).append("<p>");

        out.append("<br><b>User</b><p>");
        Principal p = securityContext.getUserPrincipal();
        if (p != null) {
            out.append("Principal: ").append(p.getName()).append("<p>");
        }

        // Access Spring security context
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof FederationAuthenticationToken) {
            out.append("Roles of user:<p><ul>");
            FederationAuthenticationToken fedAuthToken = (FederationAuthenticationToken) auth;
            for (GrantedAuthority item : fedAuthToken.getAuthorities()) {
                out.append("<li>").append(item.getAuthority()).append("</li>");
            }
            out.append("</ul>");

            if (fedAuthToken.getUserDetails() instanceof FederationUser) {
                out.append("<br><b>Claims</b><p>");
                ClaimCollection claims = ((FederationUser) fedAuthToken.getUserDetails()).getClaims();
                for (Claim c : claims) {
                    out.append(c.getClaimType().toString()).append(": ").append(c.getValue()).append("<p>");
                }
            } else {
                out.append("FederationAuthenticationToken found but not FederationUser");
            }

        } else {
            out.append("No FederationAuthenticationToken found in Spring Security Context.");
        }

        Element el = SecurityTokenThreadLocal.getToken();
        if (el != null) {
            out.append("<p>Bootstrap token...");
            String token = null;
            try {
                TransformerFactory transFactory = TransformerFactory.newInstance();
                Transformer transformer = transFactory.newTransformer();
                StringWriter buffer = new StringWriter();
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                transformer.transform(new DOMSource(el), new StreamResult(buffer));
                token = buffer.toString();
                @SuppressWarnings("deprecation")
                String escapedXml = StringEscapeUtils.escapeXml(token);
                out.append("<p>").append(escapedXml);
            } catch (Exception ex) {
                out.append("<p>Failed to transform cached element to string: ").append(ex.toString());
            }
        } else {
            out.append("<p>Bootstrap token not cached in thread local storage");
        }

        out.append("</body>");

        return rb.entity(out.toString()).build();
    }

}
