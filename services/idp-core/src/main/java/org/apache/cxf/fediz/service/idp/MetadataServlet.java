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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.metadata.IdpMetadataWriter;
import org.apache.cxf.fediz.service.idp.metadata.ServiceMetadataWriter;
import org.apache.cxf.fediz.service.idp.service.ConfigService;
import org.apache.wss4j.common.util.DOM2Writer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;


public class MetadataServlet extends HttpServlet {

    public static final String PARAM_REALM = "realm";

    private static final Logger LOG = LoggerFactory
        .getLogger(MetadataServlet.class);
    private static final long serialVersionUID = 1L;

    private ApplicationContext applicationContext;
    private String realm;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
        IOException {
        response.setContentType("text/xml; charset=utf-8");
        PrintWriter out = response.getWriter();

        ConfigService cs = (ConfigService)getApplicationContext().getBean("config");
        Idp idpConfig = cs.getIDP(realm);
        try {
            boolean isSamlRequest = request.getQueryString() != null
                && request.getQueryString().contains("protocol=saml");
            if (request.getServletPath() != null && request.getServletPath().startsWith("/metadata")) {
                String parsedRealm =
                    request.getRequestURI().substring(request.getRequestURI().indexOf("/metadata")
                                                      + "/metadata".length());
                if (parsedRealm != null && !parsedRealm.isEmpty() && parsedRealm.charAt(0) == '/') {
                    parsedRealm = parsedRealm.substring(1);
                }

                // Default to writing out the metadata for the IdP
                if (idpConfig.getRealm().equals(parsedRealm) || parsedRealm == null || parsedRealm.isEmpty()) {
                    IdpMetadataWriter mw = new IdpMetadataWriter();
                    Document metadata = mw.getMetaData(idpConfig, isSamlRequest);
                    out.write(DOM2Writer.nodeToString(metadata));
                    return;
                }

                // Otherwise try to find the metadata for the trusted third party IdP
                TrustedIdp trustedIdp = idpConfig.findTrustedIdp(parsedRealm);
                if (trustedIdp == null) {
                    LOG.error("No TrustedIdp found for desired realm: " + parsedRealm);
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                    return;
                }
                ServiceMetadataWriter mw = new ServiceMetadataWriter();
                Document metadata = mw.getMetaData(idpConfig, trustedIdp);
                out.write(DOM2Writer.nodeToString(metadata));
            } else {
                // Otherwise return the Metadata for the Idp
                LOG.debug(idpConfig.toString());
                IdpMetadataWriter mw = new IdpMetadataWriter();
                Document metadata = mw.getMetaData(idpConfig, isSamlRequest);
                out.write(DOM2Writer.nodeToString(metadata));
            }
        } catch (Exception ex) {
            LOG.error("Failed to get metadata document: ", ex);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        realm = config.getInitParameter(PARAM_REALM);
        if (realm == null || realm.length() == 0) {
            throw new ServletException("Servlet parameter '" + PARAM_REALM + "' not defined");
        }
    }

    public ApplicationContext getApplicationContext() {
        if (applicationContext == null) {
            LOG.debug(this.getServletContext().toString());
            applicationContext = WebApplicationContextUtils.getWebApplicationContext(this.getServletContext());
        }
        return applicationContext;
    }



}
