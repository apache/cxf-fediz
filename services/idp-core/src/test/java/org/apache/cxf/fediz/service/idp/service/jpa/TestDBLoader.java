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

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.cxf.fediz.service.idp.domain.FederationType;
import org.apache.cxf.fediz.service.idp.domain.TrustType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

@Transactional
public class TestDBLoader implements DBLoader {
    
    public static final String NAME = "UNITTESTDBLOADER";
    
    private static final Logger LOG = LoggerFactory.getLogger(TestDBLoader.class);
    
    private EntityManager em;

    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.em = entityManager;
    }
    
    @Override
    public String getName() {
        return NAME;
    }
    
    public void load() {
        
        try {
            ClaimEntity claimEntity5 = new ClaimEntity();
            claimEntity5.setClaimType("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/city");
            claimEntity5.setDisplayName("city");
            claimEntity5.setDescription("Description for city");
            em.persist(claimEntity5);
                        
            ApplicationEntity entity2 = new ApplicationEntity();
            entity2.setEncryptionCertificate("my encryption cert2");
            entity2.setLifeTime(1800);
            entity2.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
            entity2.setRealm("myrealm2");
            entity2.setRole("myrole");
            entity2.setServiceDescription("service description2");
            entity2.setServiceDisplayName("service displayname2");
            entity2.setTokenType("my tokentype");
            // must be persistet here already as the ApplicationClaimEntity requires the Application Id
            em.persist(entity2);
            ApplicationClaimEntity ace5 = new ApplicationClaimEntity(entity2, claimEntity5);
            ace5.setOptional(false);
            em.persist(ace5);
            entity2.getRequestedClaims().add(ace5);
            em.persist(entity2);
            
            TrustedIdpEntity entity4 = new TrustedIdpEntity();
            entity4.setCacheTokens(true);
            entity4.setCertificate("trusted cert");
            entity4.setDescription("Realm B description");
            entity4.setFederationType(FederationType.FEDERATE_IDENTITY);
            entity4.setName("Realm B");
            entity4.setProtocol("http://docs.oasis-open.org/wsfed/federation/200706");
            entity4.setRealm("trustedidp2realm");
            entity4.setTrustType(TrustType.PEER_TRUST);
            entity4.setUrl("https://localhost:${realmB.port}/fediz-idp-remote/federation");
            em.persist(entity4);
            
            em.flush();
            
        } catch (Exception ex) {
            LOG.warn("Failed to initialize DB with data", ex);
        }
    }
}
