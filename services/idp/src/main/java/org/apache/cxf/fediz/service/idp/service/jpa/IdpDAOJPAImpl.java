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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.service.IdpDAO;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public class IdpDAOJPAImpl implements IdpDAO {
    
    private static final Logger LOG = LoggerFactory.getLogger(IdpDAOJPAImpl.class);

    private EntityManager em;
    
    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.em = entityManager;
    }
    
    @Override
    public List<Idp> getIdps(int start, int size, List<String> expandList) {
        List<Idp> list = new ArrayList<Idp>();
        
        Query query = null;
        query = em.createQuery("select i from IDP i");
        
        /*List serviceEntities = query.setFirstResult(start)
            .setMaxResults(size)
            .getResultList();*/
        
        //@SuppressWarnings("rawtypes")
        List<?> idpEntities = query
            .setFirstResult(start)
            .setMaxResults(size)
            .getResultList();
    
        for (Object obj : idpEntities) {
            IdpEntity entity = (IdpEntity) obj;
            list.add(entity2domain(entity, expandList));
        }
        return list;
    }
    
    @Override
    public Idp getIdp(String realm, List<String> expandList) {
        Query query = null;
        query = em.createQuery("select i from IDP i where i.realm=:realm");
        query.setParameter("realm", realm);
        
        //@SuppressWarnings("rawtypes")
        Object idpObj = query.getSingleResult();
        return entity2domain((IdpEntity)idpObj, expandList);
    }
    
    @Override
    public Idp addIdp(Idp idp) {
        IdpEntity entity = new IdpEntity();
        domain2entity(idp, entity);
        em.persist(entity);
        
        LOG.debug("IDP '{}' added", idp.getRealm());
        return entity2domain(entity, Arrays.asList("all"));
    }

    @Override
    public void updateIdp(String realm, Idp idp) {
        Query query = null;
        query = em.createQuery("select i from IDP i where i.realm=:realm");
        query.setParameter("realm", realm);
        
        //@SuppressWarnings("rawtypes")
        IdpEntity idpEntity = (IdpEntity)query.getSingleResult();
        
        domain2entity(idp, idpEntity);
        
        em.persist(idpEntity);
        
        LOG.debug("IDP '{}' updated", idp.getRealm());
    }

    @Override
    public void deleteIdp(String realm) {
        Query query = null;
        query = em.createQuery("select i from IDP i where i.realm=:realm");
        query.setParameter("realm", realm);
        
        //@SuppressWarnings("rawtypes")
        Object idpObj = query.getSingleResult();
        em.remove(idpObj);
        
        LOG.debug("IDP '{}' deleted", realm);
    }
    
    @Override
    public void addApplicationToIdp(Idp idp, Application application) {
        IdpEntity idpEntity = null;
        if (idp.getId() != 0) {
            idpEntity = em.find(IdpEntity.class, idp.getId());
        } else {
            idpEntity = getIdpEntity(idp.getRealm(), em);
        }
        
        ApplicationEntity applicationEntity = null;
        if (application.getId() != 0) {
            applicationEntity = em.find(ApplicationEntity.class, application.getId());
        } else {
            applicationEntity = ApplicationDAOJPAImpl.getApplicationEntity(application.getRealm(), em);
        }
        
        idpEntity.getApplications().add(applicationEntity);
        
        LOG.debug("Application '{}' added to IDP '{}'", application.getRealm(), idp.getRealm());
    }
    
    @Override
    public void removeApplicationFromIdp(Idp idp, Application application) {
        IdpEntity idpEntity = null;
        if (idp.getId() != 0) {
            idpEntity = em.find(IdpEntity.class, idp.getId());
        } else {
            idpEntity = getIdpEntity(idp.getRealm(), em);
        }
        
        ApplicationEntity applicationEntity = null;
        if (application.getId() != 0) {
            applicationEntity = em.find(ApplicationEntity.class, application.getId());
        } else {
            applicationEntity = ApplicationDAOJPAImpl.getApplicationEntity(application.getRealm(), em);
        }
        
        if (applicationEntity == null) {
            throw new EntityNotFoundException("ApplicationEntity not found");
        }
        
        if (!idpEntity.getApplications().remove(applicationEntity)) {
            throw new EntityNotFoundException("ApplicationEntity not assigned to IdpEntity");
        }
                
        LOG.debug("Application '{}' removed from IDP '{}'", application.getRealm(), idp.getRealm());
    }
    
    @Override
    public void addTrustedIdpToIdp(Idp idp, TrustedIdp trustedIdp) {
        IdpEntity idpEntity = null;
        if (idp.getId() != 0) {
            idpEntity = em.find(IdpEntity.class, idp.getId());
        } else {
            idpEntity = getIdpEntity(idp.getRealm(), em);
        }
        
        TrustedIdpEntity trustedIdpEntity = null;
        if (trustedIdp.getId() != 0) {
            trustedIdpEntity = em.find(TrustedIdpEntity.class, trustedIdp.getId());
        } else {
            trustedIdpEntity = TrustedIdpDAOJPAImpl.getTrustedIdpEntity(trustedIdp.getRealm(), em);
        }
        
        idpEntity.getTrustedIdps().add(trustedIdpEntity);
        
        LOG.debug("Trusted IDP '{}' added to IDP '{}'", trustedIdp.getRealm(), idp.getRealm());
    }
    
    @Override
    public void removeTrustedIdpFromIdp(Idp idp, TrustedIdp trustedIdp) {
        IdpEntity idpEntity = null;
        if (idp.getId() != 0) {
            idpEntity = em.find(IdpEntity.class, idp.getId());
        } else {
            idpEntity = getIdpEntity(idp.getRealm(), em);
        }
        
        TrustedIdpEntity trustedIdpEntity = null;
        if (trustedIdp.getId() != 0) {
            trustedIdpEntity = em.find(TrustedIdpEntity.class, trustedIdp.getId());
        } else {
            trustedIdpEntity = TrustedIdpDAOJPAImpl.getTrustedIdpEntity(trustedIdp.getRealm(), em);
        }
        
        idpEntity.getTrustedIdps().remove(trustedIdpEntity);
        
        LOG.debug("Trusted IDP '{}' removed from IDP '{}'", trustedIdp.getRealm(), idp.getRealm());
    }
        
    @Override
    public void addClaimToIdp(Idp idp, Claim claim) {
        IdpEntity idpEntity = null;
        if (idp.getId() != 0) {
            idpEntity = em.find(IdpEntity.class, idp.getId());
        } else {
            idpEntity = getIdpEntity(idp.getRealm(), em);
        }
        
        ClaimEntity claimEntity = null;
        if (claim.getId() != 0) {
            claimEntity = em.find(ClaimEntity.class, claim.getId());
        } else {
            claimEntity = ClaimDAOJPAImpl.getClaimEntity(claim.getClaimType().toString(), em);
        }
        
        idpEntity.getClaimTypesOffered().add(claimEntity);
        
        LOG.debug("Claim '{}' added to IDP '{}'", claim.getClaimType(), idp.getRealm());
    }
    
    @Override
    public void removeClaimFromIdp(Idp idp, Claim claim) {
        IdpEntity idpEntity = null;
        if (idp.getId() != 0) {
            idpEntity = em.find(IdpEntity.class, idp.getId());
        } else {
            idpEntity = getIdpEntity(idp.getRealm(), em);
        }
        if (idpEntity == null) {
            throw new EntityNotFoundException("IdpEntity not found");
        }
        
        ClaimEntity claimEntity = null;
        if (claim.getId() != 0) {
            claimEntity = em.find(ClaimEntity.class, claim.getId());
        } else {
            claimEntity = ClaimDAOJPAImpl.getClaimEntity(claim.getClaimType().toString(), em);
        }
        if (claimEntity == null) {
            throw new EntityNotFoundException("ClaimEntity not found");
        }
        
        if (!idpEntity.getClaimTypesOffered().remove(claimEntity)) {
            throw new EntityNotFoundException("ClaimEntity not assigned to IdpEntity");
        }
        
        LOG.debug("Claim '{}' removed from IDP '{}'", claim.getClaimType(), idp.getRealm());
    }
    
    static IdpEntity getIdpEntity(String realm, EntityManager em) {
        Query query = null;
        query = em.createQuery("select i from IDP i where i.realm=:realm");
        query.setParameter("realm", realm);
        
        //@SuppressWarnings("rawtypes")
        return (IdpEntity)query.getSingleResult();
    }
    
    public static void domain2entity(Idp idp, IdpEntity entity) {
        //The ID must not be updated if the entity has got an id already (update case)
        if (idp.getId() > 0) {
            entity.setId(idp.getId());
        }
        
        entity.setCertificate(idp.getCertificate());
        entity.setCertificatePassword(idp.getCertificatePassword());
        entity.setRealm(idp.getRealm());
        entity.setServiceDescription(idp.getServiceDescription());
        entity.setServiceDisplayName(idp.getServiceDisplayName());
        entity.setHrds(idp.getHrds());
        entity.setIdpUrl(idp.getIdpUrl());
        entity.setProvideIdpList(idp.isProvideIdpList());
        entity.setStsUrl(idp.getStsUrl());
        entity.setUri(idp.getUri());
        entity.setUseCurrentIdp(idp.isUseCurrentIdp());
        entity.setRpSingleSignOutConfirmation(idp.isRpSingleSignOutConfirmation());
        entity.setRpSingleSignOutCleanupConfirmation(idp.isRpSingleSignOutCleanupConfirmation());
        
        entity.getAuthenticationURIs().clear();
        for (Map.Entry<String, String> item : idp.getAuthenticationURIs().entrySet()) {
            entity.getAuthenticationURIs().put(item.getKey(), item.getValue());
        }
        
        entity.getTokenTypesOffered().clear();
        for (String item : idp.getTokenTypesOffered()) {
            entity.getTokenTypesOffered().add(item);
        }
        
        entity.getSupportedProtocols().clear();
        for (String item : idp.getSupportedProtocols()) {
            entity.getSupportedProtocols().add(item);
        }        
    }

    
    public static Idp entity2domain(IdpEntity entity, List<String> expandList) {
        Idp idp = new Idp();
        idp.setId(entity.getId());
        idp.setCertificate(entity.getCertificate());
        idp.setCertificatePassword(entity.getCertificatePassword());
        idp.setRealm(entity.getRealm());
        idp.setServiceDescription(entity.getServiceDescription());
        idp.setServiceDisplayName(entity.getServiceDisplayName());
        idp.setHrds(entity.getHrds());
        idp.setIdpUrl(entity.getIdpUrl());
        idp.setProvideIdpList(entity.isProvideIdpList());
        idp.setStsUrl(entity.getStsUrl());
        idp.setUri(entity.getUri());
        idp.setUseCurrentIdp(entity.isUseCurrentIdp());
        idp.setRpSingleSignOutConfirmation(entity.isRpSingleSignOutConfirmation());
        idp.setRpSingleSignOutCleanupConfirmation(entity.isRpSingleSignOutCleanupConfirmation());
        
        if (expandList != null && (expandList.contains("all") || expandList.contains("applications"))) {
            for (ApplicationEntity item : entity.getApplications()) {
                Application application = ApplicationDAOJPAImpl.entity2domain(item, expandList);
                idp.getApplications().add(application);
            }
        }
        
        if (expandList != null && (expandList.contains("all") || expandList.contains("trusted-idps"))) {
            for (TrustedIdpEntity item : entity.getTrustedIdps()) {
                TrustedIdp trustedIdp = TrustedIdpDAOJPAImpl.entity2domain(item);
                idp.getTrustedIdps().add(trustedIdp);
            }
        }
        
        for (Map.Entry<String, String> item : entity.getAuthenticationURIs().entrySet()) {
            idp.getAuthenticationURIs().put(item.getKey(), item.getValue());
        }
        
        for (String item : entity.getTokenTypesOffered()) {
            idp.getTokenTypesOffered().add(item);
        }
        
        for (String item : entity.getSupportedProtocols()) {
            idp.getSupportedProtocols().add(item);
        }
        
        if (expandList != null && (expandList.contains("all") || expandList.contains("claims"))) {
            for (ClaimEntity item : entity.getClaimTypesOffered()) {
                idp.getClaimTypesOffered().add(ClaimDAOJPAImpl.entity2domain(item));
            }
        }
        
        return idp;
    }

}
