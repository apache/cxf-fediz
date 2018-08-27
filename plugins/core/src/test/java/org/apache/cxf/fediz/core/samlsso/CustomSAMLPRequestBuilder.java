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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;

/**
 * A custom SAMLPRequestBuilder instance which creates a SAML 1.1 AuthnRequest
 */
public class CustomSAMLPRequestBuilder implements SAMLPRequestBuilder {

    private boolean forceAuthn;
    private boolean isPassive;
    private String protocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    /**
     * Create a SAML 2.0 Protocol AuthnRequest
     */
    public AuthnRequest createAuthnRequest(
        String issuerId,
        String assertionConsumerServiceAddress
    ) throws Exception {
        Issuer issuer =
            SamlpRequestComponentBuilder.createIssuer(issuerId);

        NameIDPolicy nameIDPolicy =
            SamlpRequestComponentBuilder.createNameIDPolicy(
                true, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", issuerId
            );

        AuthnContextClassRef authnCtxClassRef =
            SamlpRequestComponentBuilder.createAuthnCtxClassRef(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            );
        RequestedAuthnContext authnCtx =
            SamlpRequestComponentBuilder.createRequestedAuthnCtxPolicy(
                AuthnContextComparisonTypeEnumeration.EXACT,
                Collections.singletonList(authnCtxClassRef), null
            );

        //CHECKSTYLE:OFF
        return SamlpRequestComponentBuilder.createAuthnRequest(
                assertionConsumerServiceAddress,
                forceAuthn,
                isPassive,
                protocolBinding,
                SAMLVersion.VERSION_11,
                issuer,
                nameIDPolicy,
                authnCtx
        );

    }

    public boolean isForceAuthn() {
        return forceAuthn;
    }

    public void setForceAuthn(boolean forceAuthn) {
        this.forceAuthn = forceAuthn;
    }

    public boolean isPassive() {
        return isPassive;
    }

    public void setPassive(boolean isPassive) {
        this.isPassive = isPassive;
    }

    public String getProtocolBinding() {
        return protocolBinding;
    }

    public void setProtocolBinding(String protocolBinding) {
        this.protocolBinding = protocolBinding;
    }

    @Override
    public LogoutRequest createLogoutRequest(
        String issuerId,
        String reason,
        SamlAssertionWrapper authenticatedAssertion
    ) throws Exception {
        Issuer issuer =
            SamlpRequestComponentBuilder.createIssuer(issuerId);

        NameID nameID = null;
        List<String> sessionIndices = new ArrayList<>();

        if (authenticatedAssertion != null) {
            if (authenticatedAssertion.getSaml2() != null) {
                org.opensaml.saml.saml2.core.Subject subject =
                    authenticatedAssertion.getSaml2().getSubject();
                if (subject != null && subject.getNameID() != null) {
                    nameID = subject.getNameID();
                }
            }

            if (nameID != null) {
                nameID.detach();
            }

            List<AuthnStatement> authnStatements =
                authenticatedAssertion.getSaml2().getAuthnStatements();
            if (authnStatements != null && !authnStatements.isEmpty()) {
                for (AuthnStatement authnStatement : authnStatements) {
                    if (authnStatement.getSessionIndex() != null) {
                        sessionIndices.add(authnStatement.getSessionIndex());
                    }
                }
            }
        }

        //CHECKSTYLE:OFF
        return SamlpRequestComponentBuilder.createLogoutRequest(
            issuer,
            reason,
            nameID,
            sessionIndices
        );
    }

}
