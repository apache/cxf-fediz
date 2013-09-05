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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.service.idp.model.IDPConfig;

import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.Base64;
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
    private static final XMLSignatureFactory XML_SIGNATURE_FACTORY = XMLSignatureFactory.getInstance("DOM");
    private static final DocumentBuilderFactory DOC_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
    private static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();
    
    static {
        DOC_BUILDER_FACTORY.setNamespaceAware(true);
    }

    //CHECKSTYLE:OFF
    public Document getMetaData(IDPConfig config) throws RuntimeException {
        //Return as text/xml
        try {
            
            Crypto crypto = CertsUtils.createCrypto(config.getCertificate());
            
            ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
            Writer streamWriter = new OutputStreamWriter(bout, "UTF-8");
            XMLStreamWriter writer = XML_OUTPUT_FACTORY.createXMLStreamWriter(streamWriter);

            writer.writeStartDocument();

            String referenceID = "_" + UUIDGenerator.getUUID();
            writer.writeStartElement("", "EntityDescriptor", SAML2_METADATA_NS);
            writer.writeAttribute("ID", referenceID);
                      
            writer.writeAttribute("entityID", config.getIdpUrl());

            writer.writeNamespace("fed", WS_FEDERATION_NS);
            writer.writeNamespace("wsa", WS_ADDRESSING_NS);
            writer.writeNamespace("auth", WS_FEDERATION_NS);
            writer.writeNamespace("xsi", SCHEMA_INSTANCE_NS);

            writer.writeStartElement("fed", "RoleDescriptor", WS_FEDERATION_NS);
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
            writer.writeCharacters(config.getStsUrl());
            
            writer.writeEndElement(); // Address
            writer.writeEndElement(); // EndpointReference
            writer.writeEndElement(); // SecurityTokenServiceEndpoint
            
            
            // PassiveRequestorEndpoint
            writer.writeStartElement("fed", "PassiveRequestorEndpoint", WS_FEDERATION_NS);
            writer.writeStartElement("wsa", "EndpointReference", WS_ADDRESSING_NS);

            writer.writeStartElement("wsa", "Address", WS_ADDRESSING_NS);
            writer.writeCharacters(config.getIdpUrl());
            
            writer.writeEndElement(); // Address
            writer.writeEndElement(); // EndpointReference
            writer.writeEndElement(); // PassiveRequestorEndpoint

            
            // create ClaimsType section
            if (config.getClaimTypesOffered() != null && config.getClaimTypesOffered().size() > 0) {
                writer.writeStartElement("fed", "ClaimTypesOffered", WS_FEDERATION_NS);
                for (String claim : config.getClaimTypesOffered()) {
    
                    writer.writeStartElement("auth", "ClaimType", WS_FEDERATION_NS);
                    writer.writeAttribute("Uri", claim);
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
            
            ByteArrayOutputStream result = signMetaInfo(crypto, config.getCertificatePassword(), is, referenceID);
            if (result != null) {
                is = new ByteArrayInputStream(result.toByteArray());
            } else {
                throw new RuntimeException("Failed to sign the metadata document: result=null");
            }
        
            return DOMUtils.readXml(is);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Error creating service metadata information ", e);
            throw new RuntimeException("Error creating service metadata information: " + e.getMessage());
        }

    }

    
    private ByteArrayOutputStream signMetaInfo(Crypto crypto, String keyPassword, InputStream metaInfo, String referenceID) throws Exception {
        String keyAlias = crypto.getDefaultX509Identifier(); //only one key supported in JKS
        X509Certificate cert = CertsUtils.getX509Certificate(crypto, keyAlias);
                
        // Create a Reference to the enveloped document (in this case,
        // you are signing the whole document, so a URI of "" signifies
        // that, and also specify the SHA1 digest algorithm and
        // the ENVELOPED Transform.
        Reference ref = XML_SIGNATURE_FACTORY.newReference("#" + referenceID, XML_SIGNATURE_FACTORY.newDigestMethod(DigestMethod.SHA1, null), Collections
            .singletonList(XML_SIGNATURE_FACTORY.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null)), null, null);
        
        String signatureMethod = null;
        if ("SHA1withDSA".equals(cert.getSigAlgName())) {
            signatureMethod = SignatureMethod.DSA_SHA1;
        } else if ("SHA1withRSA".equals(cert.getSigAlgName())) {
            signatureMethod = SignatureMethod.RSA_SHA1;
        } else if ("SHA256withRSA".equals(cert.getSigAlgName())) {
            signatureMethod = SignatureMethod.RSA_SHA1;
        } else {
            LOG.error("Unsupported signature method: " + cert.getSigAlgName());
            throw new RuntimeException("Unsupported signature method: " + cert.getSigAlgName());
        }
        // Create the SignedInfo.
        SignedInfo si = XML_SIGNATURE_FACTORY.newSignedInfo(XML_SIGNATURE_FACTORY.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                                                                        (C14NMethodParameterSpec)null), XML_SIGNATURE_FACTORY
            .newSignatureMethod(signatureMethod, null), Collections.singletonList(ref));
        //      .newSignatureMethod(cert.getSigAlgOID(), null), Collections.singletonList(ref));                                                                        
        
        PrivateKey keyEntry = crypto.getPrivateKey(keyAlias, keyPassword);
        
        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = XML_SIGNATURE_FACTORY.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<Object>();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        // Instantiate the document to be signed.
        Document doc = DOC_BUILDER_FACTORY.newDocumentBuilder().parse(metaInfo);

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        DOMSignContext dsc = new DOMSignContext(keyEntry, doc.getDocumentElement());
        dsc.setIdAttributeNS(doc.getDocumentElement(), null, "ID");
        dsc.setNextSibling(doc.getDocumentElement().getFirstChild());

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature signature = XML_SIGNATURE_FACTORY.newXMLSignature(si, ki);

        // Marshal, generate, and sign the enveloped signature.
        signature.sign(dsc);

        // Output the resulting document.
        ByteArrayOutputStream os = new ByteArrayOutputStream(8192);
        Transformer trans = TRANSFORMER_FACTORY.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
        os.flush();
        return os;
    }    
 
}
