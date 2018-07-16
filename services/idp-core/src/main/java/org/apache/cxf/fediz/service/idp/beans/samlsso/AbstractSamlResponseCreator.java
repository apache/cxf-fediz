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
package org.apache.cxf.fediz.service.idp.beans.samlsso;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.samlsso.SAML2PResponseComponentBuilder;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

abstract class AbstractSamlResponseCreator {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractSamlResponseCreator.class);
    private boolean signLogoutResponse = true;
    private boolean supportDeflateEncoding;
    private boolean useRealmForIssuer;

    protected Element createLogoutResponse(Idp idp, String statusValue,
                                           String destination, String requestID) throws Exception {
        Document doc = DOMUtils.newDocument();

        Status status =
            SAML2PResponseComponentBuilder.createStatus(statusValue, null);
        String issuer = useRealmForIssuer ? idp.getRealm() : idp.getIdpUrl().toString();
        LogoutResponse response =
            SAML2PResponseComponentBuilder.createSAMLLogoutResponse(requestID, issuer, status, destination);

        // Sign the LogoutResponse
        signResponse(response, idp);

        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);

        return policyElement;
    }

    protected void signResponse(SignableSAMLObject signableObject, Idp idp) throws Exception {
        if (!signLogoutResponse) {
            return;
        }
        Crypto issuerCrypto = CertsUtils.getCryptoFromCertificate(idp.getCertificate());
        String issuerKeyName = issuerCrypto.getDefaultX509Identifier();
        String issuerKeyPassword = idp.getCertificatePassword();

        Signature signature = OpenSAMLUtil.buildSignature();
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(issuerKeyName);
        X509Certificate[] issuerCerts = null;
        if (issuerCrypto != null) {
            issuerCerts = issuerCrypto.getX509Certificates(cryptoType);
        }
        if (issuerCerts == null || issuerCerts.length == 0) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                new Object[] {"No issuer certs were found to sign the SAML Assertion using issuer name: "
                                              + issuerKeyName});
        }

        String sigAlgo = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
        String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
        LOG.debug("automatic sig algo detection: {}", pubKeyAlgo);
        if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
            sigAlgo = SignatureConstants.ALGO_ID_SIGNATURE_DSA;
        } else if (pubKeyAlgo.equalsIgnoreCase("EC")) {
            sigAlgo = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1;
        }
        LOG.debug("Using Signature algorithm {}", sigAlgo);
        PrivateKey privateKey;
        try {
            privateKey = issuerCrypto.getPrivateKey(issuerKeyName, issuerKeyPassword);
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex);
        }
        if (privateKey == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                new Object[] {"No private key was found using issuer name: " + issuerKeyName});
        }

        signature.setSignatureAlgorithm(sigAlgo);

        BasicX509Credential signingCredential =
            new BasicX509Credential(issuerCerts[0], privateKey);

        signature.setSigningCredential(signingCredential);

        X509KeyInfoGeneratorFactory kiFactory = new X509KeyInfoGeneratorFactory();
        kiFactory.setEmitEntityCertificate(true);

        try {
            KeyInfo keyInfo = kiFactory.newInstance().generate(signingCredential);
            signature.setKeyInfo(keyInfo);
        } catch (org.opensaml.security.SecurityException ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex, "empty",
                new Object[] {"Error generating KeyInfo from signing credential"});
        }

        signableObject.setSignature(signature);
        String digestAlg = SignatureConstants.ALGO_ID_DIGEST_SHA1;
        SAMLObjectContentReference contentRef =
            (SAMLObjectContentReference)signature.getContentReferences().get(0);
        contentRef.setDigestAlgorithm(digestAlg);
        signableObject.releaseDOM();
        signableObject.releaseChildrenDOM(true);
    }

    protected String encodeResponse(Element response) throws IOException {
        String responseMessage = DOM2Writer.nodeToString(response);
        LOG.debug("Created Response: {}", responseMessage);

        if (supportDeflateEncoding) {
            DeflateEncoderDecoder encoder = new DeflateEncoderDecoder();
            byte[] deflatedBytes = encoder.deflateToken(responseMessage.getBytes(StandardCharsets.UTF_8));

            return Base64Utility.encode(deflatedBytes);
        }

        return Base64Utility.encode(responseMessage.getBytes());
    }

    public boolean isSupportDeflateEncoding() {
        return supportDeflateEncoding;
    }

    public void setSupportDeflateEncoding(boolean supportDeflateEncoding) {
        this.supportDeflateEncoding = supportDeflateEncoding;
    }

    public boolean isUseRealmForIssuer() {
        return useRealmForIssuer;
    }

    public void setUseRealmForIssuer(boolean useRealmForIssuer) {
        this.useRealmForIssuer = useRealmForIssuer;
    }
}
