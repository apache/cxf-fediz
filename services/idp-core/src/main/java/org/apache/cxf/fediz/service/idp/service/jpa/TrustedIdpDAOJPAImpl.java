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
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.service.TrustedIdpDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;


@Transactional
@Repository
public class TrustedIdpDAOJPAImpl implements TrustedIdpDAO {

    private static final Logger LOG = LoggerFactory.getLogger(TrustedIdpDAOJPAImpl.class);

    private EntityManager em;

    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.em = entityManager;
    }

    @Override
    public List<TrustedIdp> getTrustedIDPs(int start, int size) {
        List<TrustedIdp> list = new ArrayList<>();

        Query query = em.createQuery("select t from TrustedIDP t");

        List<?> idpEntities = query
            .setFirstResult(start)
            .setMaxResults(size)
            .getResultList();

        for (Object obj : idpEntities) {
            TrustedIdpEntity entity = (TrustedIdpEntity) obj;
            list.add(entity2domain(entity));
        }

        return list;
    }

    @Override
    public TrustedIdp getTrustedIDP(String realm) {
        return entity2domain(getTrustedIdpEntity(realm, em));
    }

    @Override
    public TrustedIdp addTrustedIDP(TrustedIdp trustedIdp) {
        TrustedIdpEntity entity = new TrustedIdpEntity();
        domain2entity(trustedIdp, entity);
        em.persist(entity);

        LOG.debug("Trusted IDP '" + trustedIdp.getRealm() + "' added");
        return entity2domain(entity);
    }

    @Override
    public void updateTrustedIDP(String realm, TrustedIdp trustedIdp) {
        TrustedIdpEntity trustedIdpEntity = getTrustedIdpEntity(realm, em);

        domain2entity(trustedIdp, trustedIdpEntity);
        em.persist(trustedIdpEntity);

        LOG.debug("Trusted IDP '" + trustedIdp.getRealm() + "' updated");
    }

    @Override
    public void deleteTrustedIDP(String realm) {
        Query query = em.createQuery("select t from TrustedIDP t where t.realm=:realm");
        query.setParameter("realm", realm);

        Object trustedIdpObj = query.getSingleResult();
        em.remove(trustedIdpObj);

        LOG.debug("Trusted IDP '" + realm + "' deleted");
    }

    static TrustedIdpEntity getTrustedIdpEntity(String realm, EntityManager em) {
        Query query = em.createQuery("select t from TrustedIDP t where t.realm=:realm");
        query.setParameter("realm", realm);

        return (TrustedIdpEntity)query.getSingleResult();
    }

    public static void domain2entity(TrustedIdp trustedIDP, TrustedIdpEntity entity) {
        //The ID must not be updated if the entity has got an id already (update case)
        if (trustedIDP.getId() > 0) {
            entity.setId(trustedIDP.getId());
        }
        entity.setCacheTokens(trustedIDP.isCacheTokens());
        entity.setCertificate(trustedIDP.getCertificate());
        entity.setDescription(trustedIDP.getDescription());
        entity.setFederationType(trustedIDP.getFederationType());
        entity.setLogo(trustedIDP.getLogo());
        entity.setName(trustedIDP.getName());
        entity.setProtocol(trustedIDP.getProtocol());
        entity.setRealm(trustedIDP.getRealm());
        entity.setIssuer(trustedIDP.getIssuer());
        entity.setTrustType(trustedIDP.getTrustType());
        entity.setUrl(trustedIDP.getUrl());
        entity.setParameters(trustedIDP.getParameters());
    }

    public static TrustedIdp entity2domain(TrustedIdpEntity entity) {
        TrustedIdp trustedIDP = new TrustedIdp();
        trustedIDP.setId(entity.getId());
        trustedIDP.setCacheTokens(entity.isCacheTokens());
        trustedIDP.setCertificate(entity.getCertificate());
        trustedIDP.setDescription(entity.getDescription());
        trustedIDP.setFederationType(entity.getFederationType());
        trustedIDP.setLogo(entity.getLogo());
        trustedIDP.setName(entity.getName());
        trustedIDP.setProtocol(entity.getProtocol());
        trustedIDP.setRealm(entity.getRealm());
        trustedIDP.setIssuer(entity.getIssuer());
        trustedIDP.setTrustType(entity.getTrustType());
        trustedIDP.setUrl(entity.getUrl());
        trustedIDP.setParameters(entity.getParameters());
        return trustedIDP;
    }

}
