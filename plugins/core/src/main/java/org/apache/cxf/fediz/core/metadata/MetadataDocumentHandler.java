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
package org.apache.cxf.fediz.core.metadata;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.SAMLSSOConstants;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.handler.RequestHandler;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.wss4j.common.util.DOM2Writer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MetadataDocumentHandler implements RequestHandler<Boolean> {

    private static final Logger LOG = LoggerFactory.getLogger(MetadataDocumentHandler.class);
    protected final FedizContext fedizConfig;

    public MetadataDocumentHandler(FedizContext fedConfig) {
        this.fedizConfig = fedConfig;
    }

    public static String getMetadataURI(FedizContext fedConfig) {
        if (fedConfig.getProtocol().getMetadataURI() != null) {
            return fedConfig.getProtocol().getMetadataURI();
        } else if (fedConfig.getProtocol() instanceof FederationProtocol) {
            return FederationConstants.METADATA_PATH_URI;
        } else if (fedConfig.getProtocol() instanceof SAMLProtocol) {
            return SAMLSSOConstants.FEDIZ_SAML_METADATA_PATH_URI;
        }
        return FederationConstants.METADATA_PATH_URI;
    }

    @Override
    public boolean canHandleRequest(HttpServletRequest request) {
        return request.getRequestURL().indexOf(MetadataDocumentHandler.getMetadataURI(fedizConfig)) != -1;
    }

    @Override
    public Boolean handleRequest(HttpServletRequest request, HttpServletResponse response) {
        LOG.debug("Metadata document requested");
        FedizProcessor wfProc = FedizProcessorFactory.newFedizProcessor(fedizConfig.getProtocol());
        PrintWriter out = null;
        try {
            out = response.getWriter();
            Document metadata = wfProc.getMetaData(request, fedizConfig);
            out.write(DOM2Writer.nodeToString(metadata));
            response.setContentType("text/xml");
            return true;
        } catch (Exception ex) {
            LOG.error("Failed to get metadata document: {}", ex.getMessage());
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            } catch (IOException e) {
                LOG.error("Failed to send error response: {}", e.getMessage());
            }
            return false;
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
}
