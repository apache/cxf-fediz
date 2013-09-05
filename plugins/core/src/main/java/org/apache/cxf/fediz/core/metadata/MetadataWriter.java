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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
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

import org.apache.cxf.fediz.core.config.Claim;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.KeyManager;
import org.apache.cxf.fediz.core.config.Protocol;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.util.DOMUtils;

import org.apache.ws.security.components.crypto.CryptoType;
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
                ByteArrayOutputStream result = signMetaInfo(config, is, referenceID);
                if (result != null) {
                    is = new ByteArrayInputStream(result.toByteArray());
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

    private ByteArrayOutputStream signMetaInfo(FederationContext config, InputStream metaInfo, String referenceID) throws Exception {
        KeyManager keyManager = config.getSigningKey();
        String keyAlias = keyManager.getKeyAlias();
        String keypass  = keyManager.getKeyPassword();
        
        // in case we did not specify the key alias, we assume there is only one key in the keystore ,
        // we use this key's alias as default. 
        if (keyAlias == null || "".equals(keyAlias)) {
            //keyAlias = getDefaultX509Identifier(ks);
            keyAlias = keyManager.getCrypto().getDefaultX509Identifier();
        }
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(keyAlias);
        X509Certificate[] issuerCerts = keyManager.getCrypto().getX509Certificates(cryptoType);
        if (issuerCerts == null || issuerCerts.length == 0) {
            throw new ProcessingException(
                    "No issuer certs were found to sign the metadata using issuer name: "
                            + keyAlias);
        }
        X509Certificate cert = issuerCerts[0];
        
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
        
        // Create a Reference to the enveloped document (in this case,
        // you are signing the whole document, so a URI of "" signifies
        // that, and also specify the SHA1 digest algorithm and
        // the ENVELOPED Transform.
        Reference ref = XML_SIGNATURE_FACTORY.newReference("#" + referenceID, XML_SIGNATURE_FACTORY.newDigestMethod(DigestMethod.SHA1, null), Collections
            .singletonList(XML_SIGNATURE_FACTORY.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null)), null, null);

        // Create the SignedInfo.
        SignedInfo si = XML_SIGNATURE_FACTORY.newSignedInfo(XML_SIGNATURE_FACTORY.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                                                                        (C14NMethodParameterSpec)null), XML_SIGNATURE_FACTORY
            .newSignatureMethod(signatureMethod, null), Collections.singletonList(ref));

        // step 2
        // Load the KeyStore and get the signing key and certificate.

        
        
        PrivateKey keyEntry = keyManager.getCrypto().getPrivateKey(keyAlias, keypass);
        
        
        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = XML_SIGNATURE_FACTORY.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<Object>();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        // step3
        // Instantiate the document to be signed.
        Document doc = DOC_BUILDER_FACTORY.newDocumentBuilder().parse(metaInfo);

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        //DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());
        DOMSignContext dsc = new DOMSignContext(keyEntry, doc.getDocumentElement());
        dsc.setIdAttributeNS(doc.getDocumentElement(), null, "ID");
        dsc.setNextSibling(doc.getDocumentElement().getFirstChild());

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature signature = XML_SIGNATURE_FACTORY.newXMLSignature(si, ki);

        // Marshal, generate, and sign the enveloped signature.
        signature.sign(dsc);

        // step 4
        // Output the resulting document.

        ByteArrayOutputStream os = new ByteArrayOutputStream(8192);
        Transformer trans = TRANSFORMER_FACTORY.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
        os.flush();
        return os;
    }

}
