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

import org.apache.cxf.fediz.service.idp.domain.Entitlement;
import org.apache.cxf.fediz.service.idp.domain.Role;
import org.apache.cxf.fediz.service.idp.service.RoleDAO;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public class RoleDAOJPAImpl implements RoleDAO {
    
    private static final Logger LOG = LoggerFactory.getLogger(RoleDAOJPAImpl.class);

    private EntityManager em;
    
    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.em = entityManager;
    }
    
    @Override
    public List<Role> getRoles(int start, int size, List<String> expandList) {
        List<Role> list = new ArrayList<>();
        
        Query query = null;
        query = em.createQuery("select r from Role r");
        
        //@SuppressWarnings("rawtypes")
        List<?> roleEntities = query
            .setFirstResult(start)
            .setMaxResults(size)
            .getResultList();
    
        for (Object obj : roleEntities) {
            RoleEntity entity = (RoleEntity) obj;
            list.add(entity2domain(entity, expandList));
        }
        return list;
    }
    
    @Override
    public Role getRole(String name, List<String> expandList) {
        Query query = null;
        query = em.createQuery("select r from Role r where r.name=:name");
        query.setParameter("name", name);
        
        //@SuppressWarnings("rawtypes")
        Object roleObj = query.getSingleResult();
        return entity2domain((RoleEntity)roleObj, expandList);
    }
    
    @Override
    public Role addRole(Role role) {
        RoleEntity entity = new RoleEntity();
        domain2entity(role, entity);
        em.persist(entity);
        
        LOG.debug("Role '{}' added", role.getName());
        return entity2domain(entity, Arrays.asList("all"));
    }

    @Override
    public void updateRole(String name, Role role) {
        Query query = null;
        query = em.createQuery("select r from Role r where r.name=:name");
        query.setParameter("name", name);
        
        //@SuppressWarnings("rawtypes")
        RoleEntity roleEntity = (RoleEntity)query.getSingleResult();
        
        domain2entity(role, roleEntity);
        
        em.persist(roleEntity);
        
        LOG.debug("Role '{}' updated", role.getName());
    }

    @Override
    public void deleteRole(String name) {
        Query query = null;
        query = em.createQuery("select r from Role r where r.name=:name");
        query.setParameter("name", name);
        
        //@SuppressWarnings("rawtypes")
        Object roleObj = query.getSingleResult();
        em.remove(roleObj);
        
        LOG.debug("Role '{}' deleted", name);
    }
    
    @Override
    public void addEntitlementToRole(Role role, Entitlement entitlement) {
        RoleEntity roleEntity = null;
        if (role.getId() != 0) {
            roleEntity = em.find(RoleEntity.class, role.getId());
        } else {
            roleEntity = getRoleEntity(role.getName(), em);
        }
        
        EntitlementEntity entitlementEntity = null;
        if (entitlement.getId() != 0) {
            entitlementEntity = em.find(EntitlementEntity.class, entitlement.getId());
        } else {
            entitlementEntity = EntitlementDAOJPAImpl.getEntitlementEntity(entitlement.getName(), em);
        }
        
        roleEntity.getEntitlements().add(entitlementEntity);
        
        LOG.debug("Entitlement '{}' added to Role '{}'", entitlement.getName(), role.getName());
    }
    
    @Override
    public void removeEntitlementFromRole(Role role, Entitlement entitlement) {
        RoleEntity roleEntity = null;
        if (role.getId() != 0) {
            roleEntity = em.find(RoleEntity.class, role.getId());
        } else {
            roleEntity = getRoleEntity(role.getName(), em);
        }
        
        EntitlementEntity entitlementEntity = null;
        if (entitlement.getId() != 0) {
            entitlementEntity = em.find(EntitlementEntity.class, entitlement.getId());
        } else {
            entitlementEntity = EntitlementDAOJPAImpl.getEntitlementEntity(entitlement.getName(), em);
        }
        
        if (entitlementEntity == null) {
            throw new EntityNotFoundException("EntitlementEntity not found");
        }
        
        if (!roleEntity.getEntitlements().remove(entitlementEntity)) {
            throw new EntityNotFoundException("EntitlementEntity not assigned to RoleEntity");
        }
        
        LOG.debug("Entitlement '{}' removed from Role '{}'", entitlement.getName(), role.getName());
    }
    
    static RoleEntity getRoleEntity(String realm, EntityManager em) {
        Query query = null;
        query = em.createQuery("select i from IDP i where i.realm=:realm");
        query.setParameter("realm", realm);
        
        //@SuppressWarnings("rawtypes")
        return (RoleEntity)query.getSingleResult();
    }
    
    public static void domain2entity(Role role, RoleEntity entity) {
        //The ID must not be updated if the entity has got an id already (update case)
        if (role.getId() > 0) {
            entity.setId(role.getId());
        }
        
        entity.setName(role.getName());
        entity.setDescription(role.getDescription());
    }

    
    public static Role entity2domain(RoleEntity entity, List<String> expandList) {
        Role role = new Role();
        role.setId(entity.getId());
        role.setName(entity.getName());
        role.setDescription(entity.getDescription());
        
        if (expandList != null && (expandList.contains("all") || expandList.contains("entitlements"))) {
            for (EntitlementEntity item : entity.getEntitlements()) {
                Entitlement entitlement = EntitlementDAOJPAImpl.entity2domain(item);
                role.getEntitlements().add(entitlement);
            }
        }
        
        return role;
    }

}
