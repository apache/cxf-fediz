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

import org.apache.cxf.fediz.service.idp.domain.Entitlement;
import org.apache.cxf.fediz.service.idp.service.EntitlementDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;


@Repository
@Transactional
public class EntitlementDAOJPAImpl implements EntitlementDAO {

    private static final Logger LOG = LoggerFactory.getLogger(EntitlementDAOJPAImpl.class);

    private EntityManager em;

    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.em = entityManager;
    }

    @Override
    public List<Entitlement> getEntitlements(int start, int size) {
        List<Entitlement> list = new ArrayList<>();

        Query query = null;
        query = em.createQuery("select e from Entitlement e");

        //@SuppressWarnings("rawtypes")
        List<?> entitlementEntities = query
            .setFirstResult(start)
            .setMaxResults(size)
            .getResultList();

        for (Object obj : entitlementEntities) {
            EntitlementEntity entity = (EntitlementEntity) obj;
            list.add(entity2domain(entity));
        }

        return list;
    }

    @Override
    public Entitlement addEntitlement(Entitlement entitlement) {
        EntitlementEntity entity = new EntitlementEntity();
        domain2entity(entitlement, entity);
        em.persist(entity);

        LOG.debug("Entitlement '{}' added", entitlement.getName());
        return entity2domain(entity);
    }

    @Override
    public Entitlement getEntitlement(String name) {
        return entity2domain(getEntitlementEntity(name, em));
    }

    @Override
    public void updateEntitlement(String name, Entitlement entitlement) {
        Query query = null;
        query = em.createQuery("select e from Entitlement e where e.name=:name");
        query.setParameter("name", name);

        //@SuppressWarnings("rawtypes")
        EntitlementEntity entitlementEntity = (EntitlementEntity)query.getSingleResult();

        domain2entity(entitlement, entitlementEntity);

        LOG.debug("Entitlement '{}' added", entitlement.getName());
        em.persist(entitlementEntity);
    }

    @Override
    public void deleteEntitlement(String name) {
        Query query = null;
        query = em.createQuery("select e from Entitlement e where e.name=:name");
        query.setParameter("name", name);

        //@SuppressWarnings("rawtypes")
        Object entitlementObj = query.getSingleResult();
        em.remove(entitlementObj);

        LOG.debug("Entitlement '{}' deleted", name);
    }

    static EntitlementEntity getEntitlementEntity(String name, EntityManager em) {
        Query query = null;
        query = em.createQuery("select e from Entitlement e where e.name=:name");
        query.setParameter("name", name);

        //@SuppressWarnings("rawtypes")
        return (EntitlementEntity)query.getSingleResult();
    }

    public static void domain2entity(Entitlement entitlement, EntitlementEntity entity) {
        //The ID must not be updated if the entity has got an id already (update case)
        if (entitlement.getId() > 0) {
            entity.setId(entitlement.getId());
        }
        //property 'internal' can't be changed, default is false
        entity.setName(entitlement.getName());
        entity.setDescription(entitlement.getDescription());
    }

    public static Entitlement entity2domain(EntitlementEntity entity) {
        Entitlement entitlement = new Entitlement();
        entitlement.setId(entity.getId());
        entitlement.setName(entity.getName());
        entitlement.setDescription(entity.getDescription());
        entitlement.setInternal(entity.isInternal());
        return entitlement;
    }

}
