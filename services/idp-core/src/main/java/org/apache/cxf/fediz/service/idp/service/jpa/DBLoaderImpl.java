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
package org.apache.cxf.fediz.service.idp.service.jpa;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.cxf.fediz.service.idp.domain.FederationType;
import org.apache.cxf.fediz.service.idp.domain.TrustType;
import org.apache.wss4j.dom.WSConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

@Transactional
public class DBLoaderImpl implements DBLoader {

    public static final String NAME = "DEMODBLOADER";

    private static final Logger LOG = LoggerFactory.getLogger(DBLoaderImpl.class);

    private EntityManager em;

    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.em = entityManager;
    }

    @Override
    public String getName() {
        return NAME;
    }

    //CHECKSTYLE:OFF: ExecutableStatementCount
    @Override
    public void load() {

        try {
            ClaimEntity claimEntity1 = new ClaimEntity();
            claimEntity1.setClaimType("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname");
            claimEntity1.setDisplayName("firstname");
            claimEntity1.setDescription("Description for firstname");
            em.persist(claimEntity1);

            ClaimEntity claimEntity2 = new ClaimEntity();
            claimEntity2.setClaimType("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname");
            claimEntity2.setDisplayName("lastname");
            claimEntity2.setDescription("Description for lastname");
            em.persist(claimEntity2);

            ClaimEntity claimEntity3 = new ClaimEntity();
            claimEntity3.setClaimType("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
            claimEntity3.setDisplayName("email");
            claimEntity3.setDescription("Description for email");
            em.persist(claimEntity3);

            ClaimEntity claimEntity4 = new ClaimEntity();
            claimEntity4.setClaimType("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role");
            claimEntity4.setDisplayName("role");
            claimEntity4.setDescription("Description for role");
            em.persist(claimEntity4);


            ApplicationEntity entity = new ApplicationEntity();
            entity.setEncryptionCertificate("");
            entity.setLifeTime(3600);
            entity.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
            entity.setRealm("urn:org:apache:cxf:fediz:fedizhelloworld");
            entity.setRole("ApplicationServiceType");
            entity.setServiceDescription("Web Application to illustrate WS-Federation");
            entity.setServiceDisplayName("Fedizhelloworld");
            entity.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
            // must be persistet here already as the ApplicationClaimEntity requires the Application Id
            em.persist(entity);
            ApplicationClaimEntity ace1 = new ApplicationClaimEntity(entity, claimEntity1);
            ace1.setOptional(true);
            em.persist(ace1);
            entity.getRequestedClaims().add(ace1);
            ApplicationClaimEntity ace2 = new ApplicationClaimEntity(entity, claimEntity2);
            ace2.setOptional(true);
            em.persist(ace2);
            entity.getRequestedClaims().add(ace2);
            ApplicationClaimEntity ace3 = new ApplicationClaimEntity(entity, claimEntity3);
            ace3.setOptional(true);
            em.persist(ace3);
            entity.getRequestedClaims().add(ace3);
            ApplicationClaimEntity ace4 = new ApplicationClaimEntity(entity, claimEntity4);
            ace4.setOptional(false);
            em.persist(ace4);
            entity.getRequestedClaims().add(ace4);
            em.persist(entity);


            TrustedIdpEntity entity3 = new TrustedIdpEntity();
            entity3.setCacheTokens(true);
            entity3.setCertificate("trusted cert");
            entity3.setDescription("Realm B description");
            entity3.setFederationType(FederationType.FEDERATE_IDENTITY);
            entity3.setName("Realm B");
            entity3.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
            entity3.setRealm("urn:org:apache:cxf:fediz:idp:realm-B");
            entity3.setTrustType(TrustType.PEER_TRUST);
            entity3.setUrl("https://localhost:12443/fediz-idp-remote/federation");
            em.persist(entity3);

            IdpEntity idpEntity = new IdpEntity();
            idpEntity.getApplications().add(entity);
            idpEntity.getTrustedIdps().add(entity3);
            idpEntity.setCertificate("stsKeystoreA.properties");
            idpEntity.setCertificatePassword("realma");
            idpEntity.setIdpUrl(new URL("https://localhost:9443/fediz-idp/federation"));
            idpEntity.setRealm("urn:org:apache:cxf:fediz:idp:realm-A");
            idpEntity.setStsUrl(new URL("https://localhost:9443/fediz-idp-sts/REALMA"));
            idpEntity.setServiceDisplayName("REALM A");
            idpEntity.setServiceDescription("IDP of Realm A");
            idpEntity.setUri("realma");
            idpEntity.setProvideIdpList(true);
            idpEntity.setAuthenticationURIs(
                Collections.singletonMap("default", "/login/default")
            );
            idpEntity.setSupportedProtocols(Arrays.asList(
                "http://docs.oasis-open.org/wsfed/federation/200706",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
            ));
            idpEntity.getClaimTypesOffered().add(claimEntity1);
            idpEntity.getClaimTypesOffered().add(claimEntity2);
            idpEntity.getClaimTypesOffered().add(claimEntity3);
            idpEntity.getClaimTypesOffered().add(claimEntity4);
            idpEntity.setTokenTypesOffered(Arrays.asList(
                WSConstants.SAML2_NS,
                WSConstants.SAML_NS
            ));
            idpEntity.setUseCurrentIdp(true);
            em.persist(idpEntity);

            em.flush();
        } catch (Exception ex) {
            LOG.warn("Failed to initialize DB with data", ex);
        }
    }
}
