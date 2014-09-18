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



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.core.config.Claim;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.Protocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.core.util.SignatureUtils;

import org.apache.ws.security.util.UUIDGenerator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.cxf.fediz.core.FederationConstants.SAML2_METADATA_NS;
import static org.apache.cxf.fediz.core.FederationConstants.SCHEMA_INSTANCE_NS;
import static org.apache.cxf.fediz.core.FederationConstants.WS_ADDRESSING_NS;
import static org.apache.cxf.fediz.core.FederationConstants.WS_FEDERATION_NS;

public class MetadataWriter {
    
    private static final Logger LOG = LoggerFactory.getLogger(MetadataWriter.class);
    
    private static final XMLOutputFactory XML_OUTPUT_FACTORY = XMLOutputFactory.newInstance();
    private static final DocumentBuilderFactory DOC_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
    
    static {
        DOC_BUILDER_FACTORY.setNamespaceAware(true);
    }

    //CHECKSTYLE:OFF
    public Document getMetaData(FederationContext config) throws ProcessingException {

        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
            Writer streamWriter = new OutputStreamWriter(bout, "UTF-8");
            XMLStreamWriter writer = XML_OUTPUT_FACTORY.createXMLStreamWriter(streamWriter);

            Protocol protocol = config.getProtocol();

            writer.writeStartDocument();

            String referenceID = "_" + UUIDGenerator.getUUID();
            writer.writeStartElement("", "EntityDescriptor", SAML2_METADATA_NS);
            writer.writeAttribute("ID", referenceID);
            
            String audience = "_someID";
            String serviceURL = null;
            if (protocol instanceof FederationProtocol) {
                serviceURL = ((FederationProtocol)protocol).getApplicationServiceURL();
                List<String> audienceList = config.getAudienceUris();
                if (audienceList != null && audienceList.size() > 0 && !"".equals(audienceList.get(0))) {
                    audience = audienceList.get(0);
                }
            }
            if (serviceURL == null) {
                serviceURL = audience;
            }
            
            writer.writeAttribute("entityID", serviceURL);

            writer.writeNamespace("fed", WS_FEDERATION_NS);
            writer.writeNamespace("wsa", WS_ADDRESSING_NS);
            writer.writeNamespace("auth", WS_FEDERATION_NS);
            writer.writeNamespace("xsi", SCHEMA_INSTANCE_NS);

            writer.writeStartElement("fed", "RoleDescriptor", WS_FEDERATION_NS);
            writer.writeAttribute(SCHEMA_INSTANCE_NS, "type", "fed:ApplicationServiceType");
            writer.writeAttribute("protocolSupportEnumeration", WS_FEDERATION_NS);

            writer.writeStartElement("fed", "ApplicationServiceEndpoint", WS_FEDERATION_NS);
            writer.writeStartElement("wsa", "EndpointReference", WS_ADDRESSING_NS);

            writer.writeStartElement("wsa", "Address", WS_ADDRESSING_NS);
            writer.writeCharacters(serviceURL);
            
            writer.writeEndElement(); // Address
            writer.writeEndElement(); // EndpointReference
            writer.writeEndElement(); // ApplicationServiceEndpoint

            // create target scope element
            writer.writeStartElement("fed", "TargetScope", WS_FEDERATION_NS);
            writer.writeStartElement("wsa", "EndpointReference", WS_ADDRESSING_NS);
            writer.writeStartElement("wsa", "Address", WS_ADDRESSING_NS);

            if (protocol instanceof FederationProtocol) {
                FederationProtocol fedprotocol = (FederationProtocol)protocol;
                
                Object realmObj = fedprotocol.getRealm();
                String realm = null;
                if (realmObj instanceof String) {
                    realm = (String)realmObj;
                } else if (realmObj instanceof CallbackHandler) {
                    //TODO
                    //If realm is resolved at runtime, metadata not updated
                }
                
                if (!(realm == null || "".equals(realm))) {
                    writer.writeCharacters(realm);
                }
            }
            // writer.writeCharacters("http://host:port/url from config");
            writer.writeEndElement(); // Address
            writer.writeEndElement(); // EndpointReference
            writer.writeEndElement(); // TargetScope

            if (protocol instanceof FederationProtocol) {
                FederationProtocol fedprotocol = (FederationProtocol)protocol;
                List<Claim> claims = fedprotocol.getClaimTypesRequested();
                if (claims != null && claims.size() > 0) {

                    // create ClaimsType section
                    writer.writeStartElement("fed", "ClaimTypesRequested", WS_FEDERATION_NS);
                    for (Claim claim : claims) {

                        writer.writeStartElement("auth", "ClaimType", WS_FEDERATION_NS);
                        writer.writeAttribute("Uri", claim.getType());
                        if (claim.isOptional()) {
                            writer.writeAttribute("Optional", "true");
                        } else {
                            writer.writeAttribute("Optional", "false");
                        }

                        writer.writeEndElement(); // ClaimType

                    }
                    writer.writeEndElement(); // ClaimsTypeRequested
                }
            }
            // create sign in endpoint section

            writer.writeStartElement("fed", "PassiveRequestorEndpoint", WS_FEDERATION_NS);
            writer.writeStartElement("wsa", "EndpointReference", WS_ADDRESSING_NS);
            writer.writeStartElement("wsa", "Address", WS_ADDRESSING_NS);

            if (protocol instanceof FederationProtocol) {
                FederationProtocol fedprotocol = (FederationProtocol)protocol;
                Object issuer = fedprotocol.getIssuer();
                if (issuer instanceof String && !"".equals(issuer)) {
                    writer.writeCharacters((String)issuer);
                }
            }

            // writer.writeCharacters("http://host:port/url Issuer from config");
            writer.writeEndElement(); // Address
            writer.writeEndElement(); // EndpointReference

            writer.writeEndElement(); // PassiveRequestorEndpoint
            writer.writeEndElement(); // RoleDescriptor
            writer.writeEndElement(); // EntityDescriptor

            writer.writeEndDocument();
            streamWriter.flush();
            bout.flush();
            //

            if (LOG.isDebugEnabled()) {
                String out = new String(bout.toByteArray());
                LOG.debug("***************** unsigned ****************");
                LOG.debug(out);
                LOG.debug("***************** unsigned ****************");
            }

            InputStream is = new ByteArrayInputStream(bout.toByteArray());
            
            boolean hasSigningKey = false;
            try {
                if (config.getSigningKey().getCrypto() != null) {
                    hasSigningKey = true;
                }
            } catch (Exception ex) {
                LOG.info("No signingKey element found in config: " + ex.getMessage());
            }
            if (hasSigningKey) {
                Document result = SignatureUtils.signMetaInfo(
                    config.getSigningKey().getCrypto(), config.getSigningKey().getKeyAlias(), config.getSigningKey().getKeyPassword(), is, referenceID);
                if (result != null) {
                    return result;
                } else {
                    throw new ProcessingException("Failed to sign the metadata document: result=null");
                }
            }
            return DOMUtils.readXml(is);
        } catch (ProcessingException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Error creating service metadata information ", e);
            throw new ProcessingException("Error creating service metadata information: " + e.getMessage());
        }

    }

    

}
