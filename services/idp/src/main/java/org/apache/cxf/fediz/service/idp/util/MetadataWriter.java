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

package org.apache.cxf.fediz.service.idp.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.core.util.SignatureUtils;
import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.utils.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.cxf.fediz.core.FedizConstants.SAML2_METADATA_NS;
import static org.apache.cxf.fediz.core.FedizConstants.SCHEMA_INSTANCE_NS;
import static org.apache.cxf.fediz.core.FedizConstants.WS_ADDRESSING_NS;
import static org.apache.cxf.fediz.core.FedizConstants.WS_FEDERATION_NS;

public class MetadataWriter {
    
    private static final Logger LOG = LoggerFactory.getLogger(MetadataWriter.class);
    
    private static final XMLOutputFactory XML_OUTPUT_FACTORY = XMLOutputFactory.newInstance();
    private static final DocumentBuilderFactory DOC_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
    
    static {
        DOC_BUILDER_FACTORY.setNamespaceAware(true);
    }

    //CHECKSTYLE:OFF
    public Document getMetaData(Idp config) throws RuntimeException {
        //Return as text/xml
        try {
            
            Crypto crypto = CertsUtils.createCrypto(config.getCertificate());
            
            ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
            Writer streamWriter = new OutputStreamWriter(bout, "UTF-8");
            XMLStreamWriter writer = XML_OUTPUT_FACTORY.createXMLStreamWriter(streamWriter);

            writer.writeStartDocument("UTF-8", "1.0");

            String referenceID = IDGenerator.generateID("_");
            writer.writeStartElement("md", "EntityDescriptor", SAML2_METADATA_NS);
            writer.writeAttribute("ID", referenceID);
                      
            writer.writeAttribute("entityID", config.getIdpUrl().toString());

            writer.writeNamespace("md", SAML2_METADATA_NS);
            writer.writeNamespace("fed", WS_FEDERATION_NS);
            writer.writeNamespace("wsa", WS_ADDRESSING_NS);
            writer.writeNamespace("auth", WS_FEDERATION_NS);
            writer.writeNamespace("xsi", SCHEMA_INSTANCE_NS);

            writer.writeStartElement("md", "RoleDescriptor", WS_FEDERATION_NS);
            writer.writeAttribute(SCHEMA_INSTANCE_NS, "type", "fed:SecurityTokenServiceType");
            writer.writeAttribute("protocolSupportEnumeration", WS_FEDERATION_NS);
            if (config.getServiceDescription() != null && config.getServiceDescription().length() > 0 ) {
                writer.writeAttribute("ServiceDescription", config.getServiceDescription());
            }
            if (config.getServiceDisplayName() != null && config.getServiceDisplayName().length() > 0 ) {
                writer.writeAttribute("ServiceDisplayName", config.getServiceDisplayName());
            }
            
            //http://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd
            //missing organization, contactperson
            
            //KeyDescriptor
            writer.writeStartElement("", "KeyDescriptor", SAML2_METADATA_NS);
            writer.writeAttribute("use", "signing");
            writer.writeStartElement("", "KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
            writer.writeStartElement("", "X509Data", "http://www.w3.org/2000/09/xmldsig#");
            writer.writeStartElement("", "X509Certificate", "http://www.w3.org/2000/09/xmldsig#");
            
            try {
                X509Certificate cert = CertsUtils.getX509Certificate(crypto, null);
                writer.writeCharacters(Base64.encode(cert.getEncoded()));
            } catch (Exception ex) {
                LOG.error("Failed to add certificate information to metadata. Metadata incomplete", ex);
            }
            
            writer.writeEndElement(); // X509Certificate
            writer.writeEndElement(); // X509Data
            writer.writeEndElement(); // KeyInfo
            writer.writeEndElement(); // KeyDescriptor
            
            
            // SecurityTokenServiceEndpoint
            writer.writeStartElement("fed", "SecurityTokenServiceEndpoint", WS_FEDERATION_NS);
            writer.writeStartElement("wsa", "EndpointReference", WS_ADDRESSING_NS);

            writer.writeStartElement("wsa", "Address", WS_ADDRESSING_NS);
            writer.writeCharacters(config.getStsUrl().toString());
            
            writer.writeEndElement(); // Address
            writer.writeEndElement(); // EndpointReference
            writer.writeEndElement(); // SecurityTokenServiceEndpoint
            
            
            // PassiveRequestorEndpoint
            writer.writeStartElement("fed", "PassiveRequestorEndpoint", WS_FEDERATION_NS);
            writer.writeStartElement("wsa", "EndpointReference", WS_ADDRESSING_NS);

            writer.writeStartElement("wsa", "Address", WS_ADDRESSING_NS);
            writer.writeCharacters(config.getIdpUrl().toString());
            
            writer.writeEndElement(); // Address
            writer.writeEndElement(); // EndpointReference
            writer.writeEndElement(); // PassiveRequestorEndpoint

            
            // create ClaimsType section
            if (config.getClaimTypesOffered() != null && config.getClaimTypesOffered().size() > 0) {
                writer.writeStartElement("fed", "ClaimTypesOffered", WS_FEDERATION_NS);
                for (Claim claim : config.getClaimTypesOffered()) {
    
                    writer.writeStartElement("auth", "ClaimType", WS_FEDERATION_NS);
                    writer.writeAttribute("Uri", claim.getClaimType().toString());
                    writer.writeAttribute("Optional", "true");
                    writer.writeEndElement(); // ClaimType
    
                }
                writer.writeEndElement(); // ClaimTypesOffered
            }
            
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
            
            Document result = SignatureUtils.signMetaInfo(crypto, null, config.getCertificatePassword(), is, referenceID);
            if (result != null) {
                return result;
            } else {
                throw new RuntimeException("Failed to sign the metadata document: result=null");
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Error creating service metadata information ", e);
            throw new RuntimeException("Error creating service metadata information: " + e.getMessage());
        }

    }

 
}
