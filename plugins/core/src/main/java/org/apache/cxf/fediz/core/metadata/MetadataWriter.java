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
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.core.config.Claim;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.Protocol;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.core.util.SignatureUtils;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.utils.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.cxf.fediz.core.FederationConstants.WS_FEDERATION_NS;
import static org.apache.cxf.fediz.core.FedizConstants.SAML2_METADATA_NS;
import static org.apache.cxf.fediz.core.FedizConstants.SCHEMA_INSTANCE_NS;
import static org.apache.cxf.fediz.core.FedizConstants.WS_ADDRESSING_NS;

public class MetadataWriter {
    
    private static final Logger LOG = LoggerFactory.getLogger(MetadataWriter.class);
    
    private static final XMLOutputFactory XML_OUTPUT_FACTORY = XMLOutputFactory.newInstance();

    //CHECKSTYLE:OFF
    public Document getMetaData(
        HttpServletRequest request, FedizContext config
    ) throws ProcessingException {

        try (ByteArrayOutputStream bout = new ByteArrayOutputStream(4096)) {
            Writer streamWriter = new OutputStreamWriter(bout, "UTF-8");
            XMLStreamWriter writer = XML_OUTPUT_FACTORY.createXMLStreamWriter(streamWriter);

            Protocol protocol = config.getProtocol();

            writer.writeStartDocument("UTF-8", "1.0");

            String referenceID = IDGenerator.generateID("_");
            writer.writeStartElement("md", "EntityDescriptor", SAML2_METADATA_NS);
            writer.writeAttribute("ID", referenceID);
            
            String serviceURL = protocol.getApplicationServiceURL();
            if (serviceURL == null) {
                serviceURL = extractFullContextPath(request);
            }
            
            writer.writeAttribute("entityID", serviceURL);
            
            writer.writeNamespace("md", SAML2_METADATA_NS);
            writer.writeNamespace("fed", WS_FEDERATION_NS);
            writer.writeNamespace("wsa", WS_ADDRESSING_NS);
            writer.writeNamespace("auth", WS_FEDERATION_NS);
            writer.writeNamespace("xsi", SCHEMA_INSTANCE_NS);

            if (protocol instanceof FederationProtocol) {
                writeFederationMetadata(writer, config, serviceURL);
            } else if (protocol instanceof SAMLProtocol) {
                writeSAMLMetadata(writer, request, config, serviceURL);
            }
            
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

            boolean hasSigningKey = false;
            try {
                if (config.getSigningKey().getCrypto() != null) {
                    hasSigningKey = true;
                }
            } catch (Exception ex) {
                LOG.info("No signingKey element found in config: " + ex.getMessage());
            }
            try (InputStream is = new ByteArrayInputStream(bout.toByteArray())) {
                if (hasSigningKey) {
                    Document doc = DOMUtils.readXml(is);
                    Document result = SignatureUtils.signMetaInfo(
                        config.getSigningKey().getCrypto(), config.getSigningKey().getKeyAlias(), config.getSigningKey().getKeyPassword(), 
                        doc, referenceID);
                    if (result != null) {
                        return result;
                    } else {
                        throw new ProcessingException("Failed to sign the metadata document: result=null");
                    }
                }
                return DOMUtils.readXml(is);
            }
        } catch (ProcessingException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Error creating service metadata information ", e);
            throw new ProcessingException("Error creating service metadata information: " + e.getMessage());
        }

    }

    private void writeFederationMetadata(
        XMLStreamWriter writer, 
        FedizContext config,
        String serviceURL
    ) throws XMLStreamException {

        writer.writeStartElement("md", "RoleDescriptor", WS_FEDERATION_NS);
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

        List<String> audienceUris = config.getAudienceUris();
        if (audienceUris != null) {
            for (String uri : audienceUris) {
                writer.writeStartElement("wsa", "EndpointReference", WS_ADDRESSING_NS);
                writer.writeStartElement("wsa", "Address", WS_ADDRESSING_NS);
                writer.writeCharacters(uri);
                writer.writeEndElement(); // Address
                writer.writeEndElement(); // EndpointReference
            }
        }
        writer.writeEndElement(); // TargetScope

        FederationProtocol protocol = (FederationProtocol)config.getProtocol();
        List<Claim> claims = protocol.getClaimTypesRequested();
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
        // create sign in endpoint section

        writer.writeStartElement("fed", "PassiveRequestorEndpoint", WS_FEDERATION_NS);
        writer.writeStartElement("wsa", "EndpointReference", WS_ADDRESSING_NS);
        writer.writeStartElement("wsa", "Address", WS_ADDRESSING_NS);

        writer.writeCharacters(serviceURL);

        // writer.writeCharacters("http://host:port/url Issuer from config");
        writer.writeEndElement(); // Address
        writer.writeEndElement(); // EndpointReference

        writer.writeEndElement(); // PassiveRequestorEndpoint
        writer.writeEndElement(); // RoleDescriptor
    }
    
    private void writeSAMLMetadata(
        XMLStreamWriter writer, 
        HttpServletRequest request,
        FedizContext config,
        String serviceURL
    ) throws Exception {
        
        SAMLProtocol protocol = (SAMLProtocol)config.getProtocol();
        
        writer.writeStartElement("md", "SPSSODescriptor", SAML2_METADATA_NS);
        writer.writeAttribute("AuthnRequestsSigned", Boolean.toString(protocol.isSignRequest()));
        writer.writeAttribute("WantAssertionsSigned", "true");
        writer.writeAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
        
        if (config.getLogoutURL() != null) {
            writer.writeStartElement("md", "SingleLogoutService", SAML2_METADATA_NS);
            
            String logoutURL = config.getLogoutURL();
            if (logoutURL.startsWith("/")) {
                logoutURL = extractFullContextPath(request).concat(logoutURL.substring(1));
            } else {
                logoutURL = extractFullContextPath(request).concat(logoutURL);
            }
            writer.writeAttribute("Location", logoutURL);
            
            writer.writeAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            writer.writeEndElement(); // SingleLogoutService
        }
        
        writer.writeStartElement("md", "AssertionConsumerService", SAML2_METADATA_NS);
        writer.writeAttribute("Location", serviceURL);
        writer.writeAttribute("index", "0");
        writer.writeAttribute("isDefault", "true");
        writer.writeAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        writer.writeEndElement(); // AssertionConsumerService
        
        if (protocol.getClaimTypesRequested() != null && !protocol.getClaimTypesRequested().isEmpty()) {
            writer.writeStartElement("md", "AttributeConsumingService", SAML2_METADATA_NS);
            writer.writeAttribute("index", "0");
            
            writer.writeStartElement("md", "ServiceName", SAML2_METADATA_NS);
            writer.writeAttribute("xml:lang", "en");
            writer.writeCharacters(config.getName());
            writer.writeEndElement(); // ServiceName
            
            for (Claim claim : protocol.getClaimTypesRequested()) {
                writer.writeStartElement("md", "RequestedAttribute", SAML2_METADATA_NS);
                writer.writeAttribute("isRequired", Boolean.toString(claim.isOptional()));
                writer.writeAttribute("Name", claim.getType());
                writer.writeAttribute("NameFormat", 
                                      "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
                writer.writeEndElement(); // RequestedAttribute
            }
            
            writer.writeEndElement(); // AttributeConsumingService
        }
        
        boolean hasSigningKey = false;
        try {
            if (config.getSigningKey().getCrypto() != null) {
                hasSigningKey = true;
            }
        } catch (Exception ex) {
            LOG.info("No signingKey element found in config: " + ex.getMessage());
        }
        if (protocol.isSignRequest() && hasSigningKey) {
            writer.writeStartElement("md", "KeyDescriptor", SAML2_METADATA_NS);
            writer.writeAttribute("use", "signing");
            
            writer.writeStartElement("ds", "KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
            writer.writeNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            writer.writeStartElement("ds", "X509Data", "http://www.w3.org/2000/09/xmldsig#");
            writer.writeStartElement("ds", "X509Certificate", "http://www.w3.org/2000/09/xmldsig#");

            // Write the Base-64 encoded certificate
            String keyAlias = config.getSigningKey().getKeyAlias();
            if (keyAlias == null || "".equals(keyAlias)) {
                keyAlias = config.getSigningKey().getCrypto().getDefaultX509Identifier();
            }
            X509Certificate cert = 
                CertsUtils.getX509Certificate(config.getSigningKey().getCrypto(), keyAlias);
            if (cert == null) {
                throw new ProcessingException(
                    "No signing certs were found to insert into the metadata using name: " 
                        + keyAlias);
            }
            byte data[] = cert.getEncoded();
            String encodedCertificate = Base64.encode(data);
            writer.writeCharacters(encodedCertificate);
            
            writer.writeEndElement(); // X509Certificate
            writer.writeEndElement(); // X509Data
            writer.writeEndElement(); // KeyInfo
            writer.writeEndElement(); // KeyDescriptor
        }
        
        writer.writeEndElement(); // SPSSODescriptor
    }

    private String extractFullContextPath(HttpServletRequest request) throws MalformedURLException {
        String result = null;
        String contextPath = request.getContextPath();
        String requestUrl = request.getRequestURL().toString();
        String requestPath = new URL(requestUrl).getPath();
        // Cut request path of request url and add context path if not ROOT
        if (requestPath != null && requestPath.length() > 0) {
            int lastIndex = requestUrl.lastIndexOf(requestPath);
            result = requestUrl.substring(0, lastIndex);
        } else {
            result = requestUrl;
        }
        if (contextPath != null && contextPath.length() > 0) {
            // contextPath contains starting slash
            result = result + contextPath + "/";
        } else {
            result = result + "/";
        }
        return result;
    }
}
