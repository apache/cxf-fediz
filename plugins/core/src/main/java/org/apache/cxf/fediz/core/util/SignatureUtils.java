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

package org.apache.cxf.fediz.core.util;

import java.io.InputStream;
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

import org.w3c.dom.Document;

import org.apache.ws.security.components.crypto.Crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class SignatureUtils {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureUtils.class);
    
    private static final XMLSignatureFactory XML_SIGNATURE_FACTORY = XMLSignatureFactory.getInstance("DOM");
    private static final DocumentBuilderFactory DOC_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
    
    static {
        DOC_BUILDER_FACTORY.setNamespaceAware(true);
    }
    
    private SignatureUtils() {
    }
    
    
    public static Document signMetaInfo(Crypto crypto, String keyAlias, String keyPassword,
                                              InputStream metaInfo, String referenceID) throws Exception {
        if (keyAlias == null || "".equals(keyAlias)) {
            keyAlias = crypto.getDefaultX509Identifier();
        }
        X509Certificate cert = CertsUtils.getX509Certificate(crypto, keyAlias);
//    }
    
/*    public static ByteArrayOutputStream signMetaInfo(FederationContext config, InputStream metaInfo,
        String referenceID)
        throws Exception {

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
*/        
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
        
        List<Transform> transformList = new ArrayList<Transform>();
        transformList.add(XML_SIGNATURE_FACTORY.newTransform(Transform.ENVELOPED, (TransformParameterSpec)null));
        transformList.add(XML_SIGNATURE_FACTORY.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                                                             (C14NMethodParameterSpec)null));
        
        // Create a Reference to the enveloped document (in this case,
        // you are signing the whole document, so a URI of "" signifies
        // that, and also specify the SHA1 digest algorithm and
        // the ENVELOPED Transform.
        Reference ref = XML_SIGNATURE_FACTORY.newReference(
            "#" + referenceID,
            XML_SIGNATURE_FACTORY.newDigestMethod(DigestMethod.SHA1, null),
            transformList,
            null, null);

        // Create the SignedInfo.
        SignedInfo si = XML_SIGNATURE_FACTORY.newSignedInfo(
            XML_SIGNATURE_FACTORY.newCanonicalizationMethod(
                CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec)null),
            XML_SIGNATURE_FACTORY.newSignatureMethod(
                signatureMethod, null), Collections.singletonList(ref));

        // step 2
        // Load the KeyStore and get the signing key and certificate.
        
        PrivateKey keyEntry = crypto.getPrivateKey(keyAlias, keyPassword);
        
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
        
        return doc;
    }
    
}
