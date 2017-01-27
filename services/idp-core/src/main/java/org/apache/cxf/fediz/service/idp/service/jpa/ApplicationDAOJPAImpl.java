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

import javax.persistence.EntityManager;
import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Claim;
import org.apache.cxf.fediz.service.idp.domain.RequestClaim;
import org.apache.cxf.fediz.service.idp.service.ApplicationDAO;
import org.apache.cxf.fediz.service.idp.service.ClaimDAO;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public class ApplicationDAOJPAImpl implements ApplicationDAO {
    
    private static final Logger LOG = LoggerFactory.getLogger(ApplicationDAOJPAImpl.class);

    private EntityManager em;
    
    @Autowired
    private ClaimDAO claimDAO;
    
    
    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.em = entityManager;
    }
    
    @Override
    public List<Application> getApplications(int start, int size, List<String> expandList) {
        List<Application> list = new ArrayList<>();
        
        Query query = null;
        query = em.createQuery("select a from Application a");
        
        //@SuppressWarnings("rawtypes")
        List<?> serviceEntities = query
            .setFirstResult(start)
            .setMaxResults(size)
            .getResultList();
    
        for (Object obj : serviceEntities) {
            ApplicationEntity entity = (ApplicationEntity) obj;
            list.add(entity2domain(entity, expandList));
        }
        return list;
    }
    
    @Override
    public Application getApplication(String realm, List<String> expandList) {
        return entity2domain(getApplicationEntity(realm, em), expandList);
    }
    
    @Override
    public Application addApplication(Application application) {
        ApplicationEntity entity = new ApplicationEntity();
        
        domain2entity(application, entity);
        em.persist(entity);
        
        LOG.debug("Application '{}' added", application.getRealm());
        return entity2domain(entity, Arrays.asList("all"));
    }

    @Override
    public void updateApplication(String realm, Application application) {
        Query query = null;
        query = em.createQuery("select a from Application a where a.realm=:realm");
        query.setParameter("realm", realm);
        
        //@SuppressWarnings("rawtypes")
        ApplicationEntity applicationEntity = (ApplicationEntity)query.getSingleResult();
        
        domain2entity(application, applicationEntity);
        
        em.persist(applicationEntity);
        
        LOG.debug("Application '{}' updated", realm);
    }
    

    @Override
    public void deleteApplication(String realm) {
        Query query = null;
        query = em.createQuery("select a from Application a where a.realm=:realm");
        query.setParameter("realm", realm);
        
        //@SuppressWarnings("rawtypes")
        Object applObj = query.getSingleResult();
        em.remove(applObj);
        
        LOG.debug("Application '{}' deleted", realm);
        
    }
    
    @Override
    public void addClaimToApplication(Application application, RequestClaim claim) {
        ApplicationEntity applicationEntity = null;
        if (application.getId() != 0) {
            applicationEntity = em.find(ApplicationEntity.class, application.getId());
        } else {
            Query query = null;
            query = em.createQuery("select a from Application a where a.realm=:realm");
            query.setParameter("realm", application.getRealm());
            
            applicationEntity = (ApplicationEntity)query.getSingleResult();
        }
        
        Claim c = claimDAO.getClaim(claim.getClaimType().toString());
        ClaimEntity claimEntity = em.find(ClaimEntity.class, c.getId());
                
        ApplicationClaimEntity appClaimEntity = new ApplicationClaimEntity();
        appClaimEntity.setClaim(claimEntity);
        appClaimEntity.setApplication(applicationEntity);
        appClaimEntity.setOptional(claim.isOptional());
        
        applicationEntity.getRequestedClaims().add(appClaimEntity);
    }
    
    @Override
    public void removeClaimFromApplication(Application application, RequestClaim claim) {
        ApplicationEntity applicationEntity = null;
        if (application.getId() != 0) {
            applicationEntity = em.find(ApplicationEntity.class, application.getId());
        } else {
            Query query = null;
            query = em.createQuery("select a from Application a where a.realm=:realm");
            query.setParameter("realm", application.getRealm());
            
            applicationEntity = (ApplicationEntity)query.getSingleResult();
        }
        
        ApplicationClaimEntity foundEntity = null;
        for (ApplicationClaimEntity acm : applicationEntity.getRequestedClaims()) {
            if (claim.getClaimType().toString().equals(acm.getClaim().getClaimType())) {
                foundEntity = acm;
                break;
            }
        }
        if (foundEntity == null) {
            throw new EntityNotFoundException("ApplicationClaimEntity not found");
        }
        
        applicationEntity.getRequestedClaims().remove(foundEntity);
    }
    
    
    static ApplicationEntity getApplicationEntity(String realm, EntityManager em) {
        Query query = null;
        query = em.createQuery("select a from Application a where a.realm=:realm");
        query.setParameter("realm", realm);
        
        //@SuppressWarnings("rawtypes")
        return (ApplicationEntity)query.getSingleResult();
    }
        
    public static void domain2entity(Application application, ApplicationEntity entity) {
        //The ID must not be updated if the entity has got an id already (update case)
        if (application.getId() > 0) {
            entity.setId(application.getId());
        }
        
        entity.setEncryptionCertificate(application.getEncryptionCertificate());
        entity.setValidatingCertificate(application.getValidatingCertificate());
        entity.setLifeTime(application.getLifeTime());
        entity.setProtocol(application.getProtocol());
        entity.setRealm(application.getRealm());
        entity.setRole(application.getRole());
        entity.setServiceDescription(application.getServiceDescription());
        entity.setServiceDisplayName(application.getServiceDisplayName());
        entity.setTokenType(application.getTokenType());
        entity.setPolicyNamespace(application.getPolicyNamespace());
        entity.setPassiveRequestorEndpoint(application.getPassiveRequestorEndpoint());
        entity.setPassiveRequestorEndpointConstraint(application.getPassiveRequestorEndpointConstraint());
        entity.setEnableAppliesTo(application.isEnableAppliesTo());
    }
    
    public static Application entity2domain(ApplicationEntity entity, List<String> expandList) {
        Application application = new Application();
        application.setId(entity.getId());
        application.setEncryptionCertificate(entity.getEncryptionCertificate());
        application.setValidatingCertificate(entity.getValidatingCertificate());
        application.setLifeTime(entity.getLifeTime());
        application.setProtocol(entity.getProtocol());
        application.setRealm(entity.getRealm());
        application.setRole(entity.getRole());
        application.setServiceDescription(entity.getServiceDescription());
        application.setServiceDisplayName(entity.getServiceDisplayName());
        application.setTokenType(entity.getTokenType());
        application.setPolicyNamespace(entity.getPolicyNamespace());
        application.setPassiveRequestorEndpoint(entity.getPassiveRequestorEndpoint());
        application.setPassiveRequestorEndpointConstraint(entity.getPassiveRequestorEndpointConstraint());
        application.setEnableAppliesTo(entity.isEnableAppliesTo());
        
        if (expandList != null && (expandList.contains("all") || expandList.contains("claims"))) {
            for (ApplicationClaimEntity item : entity.getRequestedClaims()) {
                RequestClaim claim = entity2domain(item);
                application.getRequestedClaims().add(claim);
            }
        }
        return application;
    }
    
    public static RequestClaim entity2domain(ApplicationClaimEntity entity) {
        Claim claim = ClaimDAOJPAImpl.entity2domain(entity.getClaim());
        RequestClaim reqClaim = new RequestClaim(claim);
        reqClaim.setId(entity.getId());
        reqClaim.setOptional(entity.isOptional());
        
        return reqClaim;
    }
    
    public static void domain2entity(ApplicationEntity application,
                                     RequestClaim reqClaim, ApplicationClaimEntity entity) {
        //The ID must not be updated if the entity has got an id already (update case)
        ClaimEntity claim = new ClaimEntity();
        ClaimDAOJPAImpl.domain2entity(reqClaim, claim);
        
        entity.setApplication(application);
        entity.setClaim(claim);
        entity.setOptional(reqClaim.isOptional());
    }

}
