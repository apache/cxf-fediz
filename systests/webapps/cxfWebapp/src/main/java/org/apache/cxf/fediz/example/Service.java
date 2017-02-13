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

import java.security.Principal;
import java.util.Arrays;
import java.util.List;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;

import org.w3c.dom.Element;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.fediz.core.SecurityTokenThreadLocal;
import org.apache.cxf.jaxrs.ext.MessageContext;

@Path("/secure/")
@Produces("text/html")
public class Service {
    @Context
    private MessageContext messageContext;

    @Path("/admin/fedservlet")
    @RolesAllowed("Admin")
    @GET
    public String doGetAdmin(@Context UriInfo uriInfo) throws Exception {
        return doGet(uriInfo);
    }

    @Path("/manager/fedservlet")
    @RolesAllowed("Manager")
    @GET
    public String doGetManager(@Context UriInfo uriInfo) throws Exception {
        return doGet(uriInfo);
    }

    @Path("/user/fedservlet")
    @RolesAllowed({ "User", "Admin", "Manager" })
    @GET
    public String doGetUser(@Context UriInfo uriInfo) throws Exception {
        return doGet(uriInfo);
    }

    @Path("/fedservlet")
    @RolesAllowed({ "User", "Admin", "Manager", "Authenticated", "Secretary" })
    @GET
    @Produces("text/html")
    public String doGetSecure(@Context UriInfo uriInfo) throws Exception {
        return doGet(uriInfo);
    }

    // Just used for testing purposes...
    @Path("/test.html")
    @RolesAllowed({ "User", "Admin", "Manager", "Authenticated" })
    @GET
    @Produces("text/html")
    public String doGetTest(@Context UriInfo uriInfo) throws Exception {
        StringBuilder out = new StringBuilder();
        out.append("<html>\n");
        out.append("<head><title>WS Federation Systests Examples</title></head>\n");
        out.append("<body>\n");
        out.append("<P><H3>Secure Test</H3><P></P>");
        out.append("</body>\n");

        return out.toString();
    }

    private String doGet(@Context UriInfo uriInfo) throws Exception {

        StringBuilder out = new StringBuilder();
        out.append("<html>\n");
        out.append("<head><title>WS Federation Systests Examples</title></head>\n");
        out.append("<body>\n");
        out.append("<p>Request url: " + uriInfo.getAbsolutePath() + "</p>\n");

        out.append("<p>userPrincipal=");
        Principal p = messageContext.getSecurityContext().getUserPrincipal();
        if (p != null) {
            out.append(p.getName());
        }
        out.append("</p>\n");

        List<String> roleListToCheck = Arrays.asList("Admin", "Manager", "User", "Authenticated");
        for (String item: roleListToCheck) {
            out.append("<p>role:" + item + "="
                + ((messageContext.getSecurityContext().isUserInRole(item)) ? "true" : "false")
                + "</p>\n");
        }

        if (p instanceof FedizPrincipal) {
            FedizPrincipal fp = (FedizPrincipal)p;

            ClaimCollection claims = fp.getClaims();
            for (Claim c: claims) {
                out.append("<p>" + c.getClaimType().toString() + "=" + c.getValue() + "</p>\n");
            }

            Element el = fp.getLoginToken();
            if (el != null) {
                out.append("loginToken=FOUND{FedizPrincipal}<p>\n");
            }

            el = SecurityTokenThreadLocal.getToken();
            if (el != null) {
                out.append("loginToken=FOUND{SecurityTokenThreadLocal}<p>\n");
            }

        }

        out.append("</body>\n");

        return out.toString();
    }
}
