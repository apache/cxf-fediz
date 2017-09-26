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

package org.apache.cxf.fediz.service.idp.metadata;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.w3c.dom.Document;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.core.util.SignatureUtils;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.protocols.TrustedIdpSAMLProtocolHandler;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.cxf.fediz.core.FedizConstants.SAML2_METADATA_NS;
import static org.apache.cxf.fediz.core.FedizConstants.SCHEMA_INSTANCE_NS;
import static org.apache.cxf.fediz.core.FedizConstants.WS_ADDRESSING_NS;
import static org.apache.cxf.fediz.core.FedizConstants.WS_FEDERATION_NS;

public class ServiceMetadataWriter {

    private static final Logger LOG = LoggerFactory.getLogger(ServiceMetadataWriter.class);

    //CHECKSTYLE:OFF
    public Document getMetaData(Idp config, TrustedIdp serviceConfig) throws ProcessingException {

        try {
            Crypto crypto = CertsUtils.getCryptoFromFile(config.getCertificate());

            W3CDOMStreamWriter writer = new W3CDOMStreamWriter();

            writer.writeStartDocument("UTF-8", "1.0");

            String referenceID = IDGenerator.generateID("_");
            writer.writeStartElement("md", "EntityDescriptor", SAML2_METADATA_NS);
            writer.writeAttribute("ID", referenceID);

            String serviceURL = config.getIdpUrl().toString();
            writer.writeAttribute("entityID", config.getRealm());

            writer.writeNamespace("md", SAML2_METADATA_NS);
            writer.writeNamespace("fed", WS_FEDERATION_NS);
            writer.writeNamespace("wsa", WS_ADDRESSING_NS);
            writer.writeNamespace("auth", WS_FEDERATION_NS);
            writer.writeNamespace("xsi", SCHEMA_INSTANCE_NS);

            if ("http://docs.oasis-open.org/wsfed/federation/200706".equals(serviceConfig.getProtocol())) {
                writeFederationMetadata(writer, serviceConfig, serviceURL);
            } else if ("urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser".equals(serviceConfig.getProtocol())) {
                writeSAMLMetadata(writer, serviceConfig, serviceURL, crypto);
            }

            writer.writeEndElement(); // EntityDescriptor

            writer.writeEndDocument();

            writer.close();

            if (LOG.isDebugEnabled()) {
                String out = DOM2Writer.nodeToString(writer.getDocument());
                LOG.debug("***************** unsigned ****************");
                LOG.debug(out);
                LOG.debug("***************** unsigned ****************");
            }

            Document result = SignatureUtils.signMetaInfo(crypto, null, config.getCertificatePassword(),
                                                          writer.getDocument(), referenceID);
            if (result != null) {
                return result;
            } else {
                throw new RuntimeException("Failed to sign the metadata document: result=null");
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
        TrustedIdp config,
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
        writer.writeEndElement(); // TargetScope

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
        TrustedIdp config,
        String serviceURL,
        Crypto crypto
    ) throws Exception {

        writer.writeStartElement("md", "SPSSODescriptor", SAML2_METADATA_NS);
        boolean signRequest =
            isPropertyConfigured(config, TrustedIdpSAMLProtocolHandler.SIGN_REQUEST, true);
        writer.writeAttribute("AuthnRequestsSigned", Boolean.toString(signRequest));
        writer.writeAttribute("WantAssertionsSigned", "true");
        writer.writeAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");

        writer.writeStartElement("md", "AssertionConsumerService", SAML2_METADATA_NS);
        writer.writeAttribute("Location", serviceURL);
        writer.writeAttribute("index", "0");
        writer.writeAttribute("isDefault", "true");
        writer.writeAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        writer.writeEndElement(); // AssertionConsumerService

        if (signRequest) {
            writer.writeStartElement("md", "KeyDescriptor", SAML2_METADATA_NS);
            writer.writeAttribute("use", "signing");

            writer.writeStartElement("ds", "KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
            writer.writeNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            writer.writeStartElement("ds", "X509Data", "http://www.w3.org/2000/09/xmldsig#");
            writer.writeStartElement("ds", "X509Certificate", "http://www.w3.org/2000/09/xmldsig#");

            // Write the Base-64 encoded certificate

            String keyAlias = crypto.getDefaultX509Identifier();
            X509Certificate cert = CertsUtils.getX509CertificateFromCrypto(crypto, keyAlias);

            if (cert == null) {
                throw new ProcessingException(
                    "No signing certs were found to insert into the metadata using name: "
                        + keyAlias);
            }
            byte data[] = cert.getEncoded();
            String encodedCertificate = Base64.getEncoder().encodeToString(data);
            writer.writeCharacters(encodedCertificate);

            writer.writeEndElement(); // X509Certificate
            writer.writeEndElement(); // X509Data
            writer.writeEndElement(); // KeyInfo
            writer.writeEndElement(); // KeyDescriptor
        }

        writer.writeEndElement(); // SPSSODescriptor
    }

    // Is a property configured. Defaults to "true" if not
    private boolean isPropertyConfigured(TrustedIdp trustedIdp, String property, boolean defaultValue) {
        Map<String, String> parameters = trustedIdp.getParameters();

        if (parameters != null && parameters.containsKey(property)) {
            return Boolean.parseBoolean(parameters.get(property));
        }

        return defaultValue;
    }

}
