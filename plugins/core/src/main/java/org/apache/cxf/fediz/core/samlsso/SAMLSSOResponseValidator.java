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
package org.apache.cxf.fediz.core.samlsso;

import java.time.Instant;
import java.util.List;

import org.w3c.dom.Element;

import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.DOM2Writer;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validate a SAML 2.0 Protocol Response according to the Web SSO profile. The Response
 * should be validated by the SAMLProtocolResponseValidator first.
 */
public class SAMLSSOResponseValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLSSOResponseValidator.class);

    private String issuerIDP;
    private String assertionConsumerURL;
    private String clientAddress;
    private String requestId;
    private String spIdentifier;
    private boolean enforceResponseSigned;
    private boolean enforceAssertionsSigned = true;
    private boolean enforceKnownIssuer = true;
    private ReplayCache replayCache;

    /**
     * Enforce that Assertions contained in the Response must be signed (if the Response itself is not
     * signed). The default is true.
     */
    public void setEnforceAssertionsSigned(boolean enforceAssertionsSigned) {
        this.enforceAssertionsSigned = enforceAssertionsSigned;
    }

    /**
     * Enforce that the Issuer of the received Response/Assertion is known. The default is true.
     */
    public void setEnforceKnownIssuer(boolean enforceKnownIssuer) {
        this.enforceKnownIssuer = enforceKnownIssuer;
    }

    /**
     * Validate a SAML 2 Protocol Response
     * @param samlResponse
     * @param postBinding
     * @return a SSOValidatorResponse object
     * @throws WSSecurityException
     */
    public SSOValidatorResponse validateSamlResponse(
        org.opensaml.saml.saml2.core.Response samlResponse,
        boolean postBinding
    ) throws WSSecurityException {
        // Check the Issuer
        validateIssuer(samlResponse.getIssuer());

        // The Response must contain at least one Assertion.
        if (samlResponse.getAssertions() == null || samlResponse.getAssertions().isEmpty()) {
            LOG.debug("The Response must contain at least one Assertion");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // The Response must contain a Destination that matches the assertionConsumerURL if it is
        // signed
        String destination = samlResponse.getDestination();
        if (samlResponse.isSigned()
            && (destination == null || !destination.equals(assertionConsumerURL))) {
            LOG.debug("The Response must contain a destination that matches the assertion consumer URL");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        if (enforceResponseSigned && !samlResponse.isSigned()) {
            LOG.debug("The Response must be signed!");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // Validate Assertions
        org.opensaml.saml.saml2.core.Assertion validAssertion = null;
        Instant sessionNotOnOrAfter = null;
        for (org.opensaml.saml.saml2.core.Assertion assertion : samlResponse.getAssertions()) {
            // Check the Issuer
            if (assertion.getIssuer() == null) {
                LOG.debug("Assertion Issuer must not be null");
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
            }
            validateIssuer(assertion.getIssuer());

            if (!samlResponse.isSigned() && enforceAssertionsSigned && assertion.getSignature() == null) {
                LOG.debug("The enclosed assertions in the SAML Response must be signed");
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
            }

            // Check for AuthnStatements and validate the Subject accordingly
            if (assertion.getAuthnStatements() != null
                && !assertion.getAuthnStatements().isEmpty()) {
                org.opensaml.saml.saml2.core.Subject subject = assertion.getSubject();
                if (validateAuthenticationSubject(subject, assertion.getID(), postBinding)) {
                    validateAudienceRestrictionCondition(assertion.getConditions());
                    validAssertion = assertion;
                    // Store Session NotOnOrAfter
                    for (AuthnStatement authnStatment : assertion.getAuthnStatements()) {
                        if (authnStatment.getSessionNotOnOrAfter() != null) {
                            sessionNotOnOrAfter = authnStatment.getSessionNotOnOrAfter().toDate().toInstant();
                        }
                    }
                }
            }

        }

        if (validAssertion == null) {
            LOG.debug("The Response did not contain any Authentication Statement that matched "
                     + "the Subject Confirmation criteria");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        SSOValidatorResponse validatorResponse = new SSOValidatorResponse();
        validatorResponse.setResponseId(samlResponse.getID());
        validatorResponse.setSessionNotOnOrAfter(sessionNotOnOrAfter);

        Element assertionElement = validAssertion.getDOM();
        Element clonedAssertionElement = (Element)assertionElement.cloneNode(true);
        validatorResponse.setAssertionElement(clonedAssertionElement);
        validatorResponse.setAssertion(DOM2Writer.nodeToString(clonedAssertionElement));

        return validatorResponse;
    }

    /**
     * Validate the Issuer (if it exists)
     */
    private void validateIssuer(org.opensaml.saml.saml2.core.Issuer issuer) throws WSSecurityException {
        if (issuer == null) {
            return;
        }

        // Issuer value must match (be contained in) Issuer IDP
        if (enforceKnownIssuer && issuerIDP != null && !issuerIDP.startsWith(issuer.getValue())) {
            LOG.debug("Issuer value: " + issuer.getValue() + " does not match issuer IDP: "
                + issuerIDP);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // Format must be nameid-format-entity
        if (issuer.getFormat() != null
            && !SAML2Constants.NAMEID_FORMAT_ENTITY.equals(issuer.getFormat())) {
            LOG.debug("Issuer format is not null and does not equal: "
                + SAML2Constants.NAMEID_FORMAT_ENTITY);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
    }

    /**
     * Validate the Subject (of an Authentication Statement).
     */
    private boolean validateAuthenticationSubject(
        org.opensaml.saml.saml2.core.Subject subject, String id, boolean postBinding
    ) throws WSSecurityException {
        if (subject.getSubjectConfirmations() == null) {
            return false;
        }

        boolean foundBearerSubjectConf = false;
        // We need to find a Bearer Subject Confirmation method
        for (org.opensaml.saml.saml2.core.SubjectConfirmation subjectConf
            : subject.getSubjectConfirmations()) {
            if (SAML2Constants.CONF_BEARER.equals(subjectConf.getMethod())) {
                foundBearerSubjectConf = true;
                validateSubjectConfirmation(subjectConf.getSubjectConfirmationData(), id, postBinding);
            }
        }

        return foundBearerSubjectConf;
    }

    /**
     * Validate a (Bearer) Subject Confirmation
     */
    private void validateSubjectConfirmation(
        org.opensaml.saml.saml2.core.SubjectConfirmationData subjectConfData, String id, boolean postBinding
    ) throws WSSecurityException {
        if (subjectConfData == null) {
            LOG.debug("Subject Confirmation Data of a Bearer Subject Confirmation is null");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // Recipient must match assertion consumer URL
        String recipient = subjectConfData.getRecipient();
        if (recipient == null || !recipient.equals(assertionConsumerURL)) {
            LOG.debug("Recipient " + recipient + " does not match assertion consumer URL "
                + assertionConsumerURL);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // We must have a NotOnOrAfter timestamp
        if (subjectConfData.getNotOnOrAfter() == null
            || subjectConfData.getNotOnOrAfter().isBeforeNow()) {
            LOG.debug("Subject Conf Data does not contain NotOnOrAfter or it has expired");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // Need to keep bearer assertion IDs based on NotOnOrAfter to detect replay attacks
        if (postBinding && replayCache != null) {
            if (replayCache.contains(id)) {
                Instant expires = subjectConfData.getNotOnOrAfter().toDate().toInstant();
                replayCache.add(id, expires);
            } else {
                LOG.debug("Replay attack with token id: " + id);
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
            }
        }

        // Check address
        if (subjectConfData.getAddress() != null && clientAddress != null
            && !subjectConfData.getAddress().equals(clientAddress)) {
            LOG.debug("Subject Conf Data address " + subjectConfData.getAddress() + " does not match"
                     + " client address " + clientAddress);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // It must not contain a NotBefore timestamp
        if (subjectConfData.getNotBefore() != null) {
            LOG.debug("The Subject Conf Data must not contain a NotBefore timestamp");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

        // InResponseTo must match the AuthnRequest request Id
        if (requestId != null && !requestId.equals(subjectConfData.getInResponseTo())) {
            LOG.debug("The InResponseTo String " + subjectConfData.getInResponseTo()
                     + " does match the original request id " + requestId);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }

    }

    private void validateAudienceRestrictionCondition(
        org.opensaml.saml.saml2.core.Conditions conditions
    ) throws WSSecurityException {
        if (conditions == null) {
            LOG.debug("Conditions are null");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
        List<AudienceRestriction> audienceRestrs = conditions.getAudienceRestrictions();
        if (spIdentifier != null && !matchSaml2AudienceRestriction(spIdentifier, audienceRestrs)) {
            LOG.debug("Assertion does not contain unique subject provider identifier "
                     + spIdentifier + " in the audience restriction conditions");
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
        }
    }


    private boolean matchSaml2AudienceRestriction(
        String appliesTo, List<AudienceRestriction> audienceRestrictions
    ) {
        boolean found = false;
        if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
            for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                if (audienceRestriction.getAudiences() != null) {
                    for (org.opensaml.saml.saml2.core.Audience audience : audienceRestriction.getAudiences()) {
                        if (appliesTo.equals(audience.getAudienceURI())) {
                            return true;
                        }
                    }
                }
            }
        }

        return found;
    }

    public String getIssuerIDP() {
        return issuerIDP;
    }

    public void setIssuerIDP(String issuerIDP) {
        this.issuerIDP = issuerIDP;
    }

    public String getAssertionConsumerURL() {
        return assertionConsumerURL;
    }

    public void setAssertionConsumerURL(String assertionConsumerURL) {
        this.assertionConsumerURL = assertionConsumerURL;
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public void setClientAddress(String clientAddress) {
        this.clientAddress = clientAddress;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getSpIdentifier() {
        return spIdentifier;
    }

    public void setSpIdentifier(String spIdentifier) {
        this.spIdentifier = spIdentifier;
    }

    public void setReplayCache(ReplayCache replayCache) {
        this.replayCache = replayCache;
    }

    public boolean isEnforceResponseSigned() {
        return enforceResponseSigned;
    }

    /**
     * Enforce whether a SAML Response must be signed.
     */
    public void setEnforceResponseSigned(boolean enforceResponseSigned) {
        this.enforceResponseSigned = enforceResponseSigned;
    }
}
