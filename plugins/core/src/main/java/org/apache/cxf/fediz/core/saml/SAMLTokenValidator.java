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

package org.apache.cxf.fediz.core.saml;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.TokenValidator;
import org.apache.cxf.fediz.core.TokenValidatorRequest;
import org.apache.cxf.fediz.core.TokenValidatorResponse;
import org.apache.cxf.fediz.core.config.CertificateValidationMethod;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.config.Protocol;
import org.apache.cxf.fediz.core.config.SAMLProtocol;
import org.apache.cxf.fediz.core.config.TrustManager;
import org.apache.cxf.fediz.core.config.TrustedIssuer;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.saml.FedizSignatureTrustValidator.TrustType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.SAMLTokenPrincipal;
import org.apache.wss4j.common.principal.SAMLTokenPrincipalImpl;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.wss4j.dom.validate.Credential;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SAMLTokenValidator implements TokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLTokenValidator.class);


    @Override
    public boolean canHandleTokenType(String tokenType) {
        return WSConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType) || WSConstants.SAML2_NS.equals(tokenType)
            || WSConstants.WSS_SAML_TOKEN_TYPE.equals(tokenType) || WSConstants.SAML_NS.equals(tokenType);
    }

    @Override
    public boolean canHandleToken(Element token) {
        String ns = token.getNamespaceURI();
        return WSConstants.SAML2_NS.equals(ns) || WSConstants.SAML_NS.equals(ns);
    }

    public TokenValidatorResponse validateAndProcessToken(TokenValidatorRequest request,
            FedizContext config) throws ProcessingException {

        Element token = request.getToken();
        try {
            RequestData requestData = new RequestData();
            WSSConfig wssConfig = WSSConfig.getNewInstance();
            requestData.setWssConfig(wssConfig);
            requestData.setWsDocInfo(new WSDocInfo(token.getOwnerDocument()));
            // not needed as no private key must be read
            // requestData.setCallbackHandler(new
            // PasswordCallbackHandler(password));

            SamlAssertionWrapper assertion = new SamlAssertionWrapper(token);
            
            boolean doNotEnforceAssertionsSigned =
                    ((SAMLProtocol)config.getProtocol()).isDoNotEnforceAssertionsSigned();
            
            boolean trusted = doNotEnforceAssertionsSigned;
            String assertionIssuer = assertion.getIssuerString();
            
            if (!doNotEnforceAssertionsSigned) {
                if (!assertion.isSigned()) {
                    LOG.warn("Assertion is not signed");
                    throw new ProcessingException(TYPE.TOKEN_NO_SIGNATURE);
                }
                // Verify the signature
                Signature sig = assertion.getSignature();
                KeyInfo keyInfo = sig.getKeyInfo();
                SAMLKeyInfo samlKeyInfo =
                    org.apache.wss4j.common.saml.SAMLUtil.getCredentialFromKeyInfo(
                        keyInfo.getDOM(), new WSSSAMLKeyInfoProcessor(requestData),
                        requestData.getSigVerCrypto()
                    );
                assertion.verifySignature(samlKeyInfo);

                // Parse the subject if it exists
                assertion.parseSubject(
                    new WSSSAMLKeyInfoProcessor(requestData), requestData.getSigVerCrypto(),
                    requestData.getCallbackHandler()
                );

                // Now verify trust on the signature
                Credential trustCredential = new Credential();
                trustCredential.setPublicKey(samlKeyInfo.getPublicKey());
                trustCredential.setCertificates(samlKeyInfo.getCerts());
                trustCredential.setSamlAssertion(assertion);

                SamlAssertionValidator trustValidator = new SamlAssertionValidator();
                trustValidator.setFutureTTL(config.getMaximumClockSkew().intValue());
           
                List<TrustedIssuer> trustedIssuers = config.getTrustedIssuers();
                for (TrustedIssuer ti : trustedIssuers) {
                    Pattern subjectConstraint = ti.getCompiledSubject();
                    List<Pattern> subjectConstraints = new ArrayList<>(1);
                    if (subjectConstraint != null) {
                        subjectConstraints.add(subjectConstraint);
                    }
                
                    if (ti.getCertificateValidationMethod().equals(CertificateValidationMethod.CHAIN_TRUST)) {
                        trustValidator.setSubjectConstraints(subjectConstraints);
                        trustValidator.setSignatureTrustType(TrustType.CHAIN_TRUST_CONSTRAINTS);
                    } else if (ti.getCertificateValidationMethod().equals(CertificateValidationMethod.PEER_TRUST)) {
                        trustValidator.setSignatureTrustType(TrustType.PEER_TRUST);
                    } else {
                        throw new IllegalStateException("Unsupported certificate validation method: "
                                                        + ti.getCertificateValidationMethod());
                    }
                    try {
                        for (TrustManager tm: config.getCertificateStores()) {
                            try {
                                requestData.setSigVerCrypto(tm.getCrypto());
                                trustValidator.validate(trustCredential, requestData);
                                trusted = true;
                                break;
                            } catch (Exception ex) {
                                LOG.debug("Issuer '{}' not validated in keystore '{}'",
                                          ti.getName(), tm.getName());
                            }
                        }
                        if (trusted) {
                            break;
                        }
                
                    } catch (Exception ex) {
                        if (LOG.isInfoEnabled()) {
                            LOG.info("Issuer '" + assertionIssuer + "' doesn't match trusted issuer '" + ti.getName()
                                     + "': " + ex.getMessage());
                        }
                    }
                }
            }

            if (!trusted) {
                // Condition already checked in SamlAssertionValidator
                // Minor performance impact on untrusted and expired tokens
                if (!isConditionValid(assertion, config.getMaximumClockSkew().intValue())) {
                    LOG.warn("Security token expired");
                    throw new ProcessingException(TYPE.TOKEN_EXPIRED);
                } else {
                    LOG.warn("Issuer '" + assertionIssuer + "' not trusted");
                    throw new ProcessingException(TYPE.ISSUER_NOT_TRUSTED);
                }
            }

            // Now check for HolderOfKey requirements
            if (!SAMLUtil.checkHolderOfKey(assertion, request.getCerts())) {
                LOG.warn("Assertion fails holder-of-key requirements");
                throw new ProcessingException(TYPE.ISSUER_NOT_TRUSTED);
            }

            String audience = null;
            List<Claim> claims = null;
            if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)) {
                claims = parseClaimsInAssertion(assertion.getSaml2());
                audience = getAudienceRestriction(assertion.getSaml2());
            } else if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_11)) {
                claims = parseClaimsInAssertion(assertion.getSaml1());
                audience = getAudienceRestriction(assertion.getSaml1());
            } else {
                claims = Collections.emptyList();
            }

            claims = parseRoleClaim(config, claims);
            
            SAMLTokenPrincipal p = new SAMLTokenPrincipalImpl(assertion);

            TokenValidatorResponse response = new TokenValidatorResponse(
                    assertion.getId(), p.getName(), assertionIssuer,
                    new ClaimCollection(claims), audience);
            response.setExpires(getExpires(assertion));
            response.setCreated(getCreated(assertion));

            return response;

        } catch (WSSecurityException ex) {
            LOG.error("Security token validation failed", ex);
            throw new ProcessingException(TYPE.TOKEN_INVALID);
        }
    }

    protected List<Claim> parseRoleClaim(FedizContext config, List<Claim> claims) {
        Protocol protocol = config.getProtocol();
        if (protocol.getRoleURI() != null) {
            URI roleURI = URI.create(protocol.getRoleURI());
            String delim = protocol.getRoleDelimiter();
            for (Claim c : claims) {
                if (roleURI.equals(c.getClaimType())) {
                    final List<String> roles;
                    Object oValue = c.getValue();
                    if (oValue instanceof String) {
                        if (delim == null || "".equals(oValue)) {
                            roles = Collections.singletonList((String)oValue);
                        } else {
                            roles = parseRoles((String)oValue, delim);
                        }
                    } else if (oValue instanceof List<?>) {
                        @SuppressWarnings("unchecked")
                        List<String> values = (List<String>)oValue;
                        roles = Collections.unmodifiableList(values);
                    } else {
                        LOG.error("Unsupported value type of Claim value");
                        throw new IllegalStateException("Unsupported value type of Claim value");
                    }
                    // Replace single role String with role List<String> after parsing
                    c.setValue(roles);
                    break;
                }
            }
        }
        return claims;
    }

    protected List<Claim> parseClaimsInAssertion(
            org.opensaml.saml.saml1.core.Assertion assertion) {
        List<org.opensaml.saml.saml1.core.AttributeStatement> attributeStatements = assertion
                .getAttributeStatements();
        if (attributeStatements == null || attributeStatements.isEmpty()) {
            LOG.debug("No attribute statements found");
            return Collections.emptyList();
        }
        List<Claim> collection = new ArrayList<>();
        Map<String, Claim> claimsMap = new HashMap<>();

        for (org.opensaml.saml.saml1.core.AttributeStatement statement : attributeStatements) {
            LOG.debug("parsing statement: {}", statement.getElementQName());

            List<org.opensaml.saml.saml1.core.Attribute> attributes = statement
                    .getAttributes();
            for (org.opensaml.saml.saml1.core.Attribute attribute : attributes) {
                LOG.debug("parsing attribute: {}", attribute.getAttributeName());
                Claim c = new Claim();
                c.setIssuer(assertion.getIssuer());
                if (attribute.getAttributeNamespace() != null) {
                    URI attrName = URI.create(attribute.getAttributeName());
                    if (attrName.isAbsolute()) {
                        // Workaround for CXF-4484
                        c.setClaimType(attrName);
                        if (attribute.getAttributeName().startsWith(attribute.getAttributeNamespace())) {
                            LOG.info("AttributeName fully qualified '" + attribute.getAttributeName()
                                     + "' but does match with AttributeNamespace '"
                                     + attribute.getAttributeNamespace() + "'");
                        } else {
                            LOG.warn("AttributeName fully qualified '" + attribute.getAttributeName()
                                     + "' but does NOT match with AttributeNamespace (ignored) '"
                                     + attribute.getAttributeNamespace() + "'");
                        }
                    } else {
                        if (attribute.getAttributeNamespace().endsWith("/")) {
                            c.setClaimType(URI.create(attribute.getAttributeNamespace()
                                                      + attribute.getAttributeName()));
                        } else {
                            c.setClaimType(URI.create(attribute.getAttributeNamespace()
                                                      + "/" + attribute.getAttributeName()));
                        }
                    }
                } else {
                    c.setClaimType(URI.create(attribute.getAttributeName()));
                }
                List<String> valueList = new ArrayList<>();
                for (XMLObject attributeValue : attribute.getAttributeValues()) {
                    Element attributeValueElement = attributeValue.getDOM();
                    String value = attributeValueElement.getTextContent();
                    LOG.debug(" [{}]", value);
                    valueList.add(value);
                }
                mergeClaimToMap(claimsMap, c, valueList);
            }
        }
        collection.addAll(claimsMap.values());
        return collection;
    }

    protected List<Claim> parseClaimsInAssertion(
            org.opensaml.saml.saml2.core.Assertion assertion) {
        List<org.opensaml.saml.saml2.core.AttributeStatement> attributeStatements = assertion
                .getAttributeStatements();
        if (attributeStatements == null || attributeStatements.isEmpty()) {
            LOG.debug("No attribute statements found");
            return Collections.emptyList();
        }

        List<Claim> collection = new ArrayList<>();
        Map<String, Claim> claimsMap = new HashMap<>();

        for (org.opensaml.saml.saml2.core.AttributeStatement statement : attributeStatements) {
            LOG.debug("parsing statement: {}", statement.getElementQName());
            List<org.opensaml.saml.saml2.core.Attribute> attributes = statement
                    .getAttributes();
            for (org.opensaml.saml.saml2.core.Attribute attribute : attributes) {
                LOG.debug("parsing attribute: {}", attribute.getName());
                Claim c = new Claim();
                // Workaround for CXF-4484
                // Value of Attribute Name not fully qualified
                // if NameFormat is http://schemas.xmlsoap.org/ws/2005/05/identity/claims
                // but ClaimType value must be fully qualified as Namespace attribute goes away
                URI attrName = URI.create(attribute.getName());
                if (ClaimTypes.URI_BASE.toString().equals(attribute.getNameFormat())
                    && !attrName.isAbsolute()) {
                    c.setClaimType(URI.create(ClaimTypes.URI_BASE + "/" + attribute.getName()));
                } else {
                    c.setClaimType(URI.create(attribute.getName()));
                }
                c.setIssuer(assertion.getIssuer().getNameQualifier());

                List<String> valueList = new ArrayList<>();
                for (XMLObject attributeValue : attribute.getAttributeValues()) {
                    Element attributeValueElement = attributeValue.getDOM();
                    String value = attributeValueElement.getTextContent();
                    LOG.debug(" [{}]", value);
                    valueList.add(value);
                }
                mergeClaimToMap(claimsMap, c, valueList);
            }
        }
        collection.addAll(claimsMap.values());
        return collection;

    }

    protected void mergeClaimToMap(Map<String, Claim> claimsMap, Claim c,
            List<String> valueList) {
        Claim t = claimsMap.get(c.getClaimType().toString());
        if (t != null) {
            //same SAML attribute already processed. Thus Claim object already created.
            Object oValue = t.getValue();
            if (oValue instanceof String) {
                //one child element AttributeValue only
                List<String> values = new ArrayList<>();
                values.add((String)oValue); //add existing value
                values.addAll(valueList);
                t.setValue(values);
            } else if (oValue instanceof List<?>) {
                //more than one child element AttributeValue
                @SuppressWarnings("unchecked")
                List<String> values = (List<String>)oValue;
                values.addAll(valueList);
                t.setValue(values);
            } else {
                LOG.error("Unsupported value type of Claim value");
                throw new IllegalStateException("Unsupported value type of Claim value");
            }
        } else {
            if (valueList.size() == 1) {
                c.setValue(valueList.get(0));
            } else {
                c.setValue(valueList);
            }
            // Add claim to map
            claimsMap.put(c.getClaimType().toString(), c);
        }
    }

    protected List<String> parseRoles(String value, String delim) {
        List<String> roles = new ArrayList<>();
        StringTokenizer st = new StringTokenizer(value, delim);
        while (st.hasMoreTokens()) {
            String role = st.nextToken();
            roles.add(role);
        }
        return roles;
    }

    protected String getAudienceRestriction(
            org.opensaml.saml.saml1.core.Assertion assertion) {
        String audience = null;
        try {
            audience = assertion.getConditions()
                    .getAudienceRestrictionConditions().get(0).getAudiences()
                    .get(0).getUri();
        } catch (Exception ex) {
            LOG.warn("Failed to read audience" + ex.getMessage());
        }
        return audience;
    }

    protected String getAudienceRestriction(
            org.opensaml.saml.saml2.core.Assertion assertion) {
        String audience = null;
        try {
            audience = assertion.getConditions().getAudienceRestrictions()
                    .get(0).getAudiences().get(0).getAudienceURI();
        } catch (Exception ex) {
            LOG.warn("Failed to read audience" + ex.getMessage());
        }
        return audience;

    }


    private Instant getExpires(SamlAssertionWrapper assertion) {
        DateTime validTill = null;
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)) {
            validTill = assertion.getSaml2().getConditions().getNotOnOrAfter();
        } else {
            validTill = assertion.getSaml1().getConditions().getNotOnOrAfter();
        }

        if (validTill == null) {
            return null;
        }
        return validTill.toDate().toInstant();
    }

    private Instant getCreated(SamlAssertionWrapper assertion) {
        DateTime validFrom = null;
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)) {
            validFrom = assertion.getSaml2().getConditions().getNotBefore();
        } else {
            validFrom = assertion.getSaml1().getConditions().getNotBefore();
        }

        if (validFrom == null) {
            return null;
        }
        return validFrom.toDate().toInstant();
    }

    /**
     * Check the Conditions of the Assertion.
     */
    protected boolean isConditionValid(SamlAssertionWrapper assertion, int maxClockSkew) throws WSSecurityException {
        DateTime validFrom = null;
        DateTime validTill = null;
        if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_20)
            && assertion.getSaml2().getConditions() != null) {
            validFrom = assertion.getSaml2().getConditions().getNotBefore();
            validTill = assertion.getSaml2().getConditions().getNotOnOrAfter();
        } else if (assertion.getSamlVersion().equals(SAMLVersion.VERSION_11)
            && assertion.getSaml1().getConditions() != null) {
            validFrom = assertion.getSaml1().getConditions().getNotBefore();
            validTill = assertion.getSaml1().getConditions().getNotOnOrAfter();
        }

        if (validFrom != null) {
            DateTime currentTime = new DateTime();
            currentTime = currentTime.plusSeconds(maxClockSkew);
            if (validFrom.isAfter(currentTime)) {
                LOG.debug("SAML Token condition (Not Before) not met");
                return false;
            }
        }

        if (validTill != null && validTill.isBeforeNow()) {
            LOG.debug("SAML Token condition (Not On Or After) not met");
            return false;
        }
        return true;
    }


}
