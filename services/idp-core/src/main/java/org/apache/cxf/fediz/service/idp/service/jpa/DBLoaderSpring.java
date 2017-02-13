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

import java.util.Collection;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.transaction.annotation.Transactional;

@Transactional
public class DBLoaderSpring implements DBLoader {

    public static final String NAME = "SPRINGDBLOADER";

    private static final Logger LOG = LoggerFactory.getLogger(DBLoaderSpring.class);

    private EntityManager em;
    private String resource;

    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.em = entityManager;
    }

    @Override
    public String getName() {
        return NAME;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    @Override
    public void load() {

        GenericXmlApplicationContext ctx = null;
        try {

            if (resource == null) {
                LOG.warn("Resource null for DBLoaderSpring");
            }

            ctx = new GenericXmlApplicationContext();
            ctx.load(resource);
            ctx.refresh();
            ctx.start();

            Collection<EntitlementEntity> entitlements = ctx.
                getBeansOfType(EntitlementEntity.class, true, true).values();
            for (EntitlementEntity e : entitlements) {
                em.persist(e);
            }
            LOG.info(entitlements.size() + " EntitlementEntity added");

            Collection<RoleEntity> roles = ctx.
                getBeansOfType(RoleEntity.class, true, true).values();
            for (RoleEntity r : roles) {
                em.persist(r);
            }
            LOG.info(roles.size() + " RoleEntity added");

            Collection<ClaimEntity> claims = ctx.getBeansOfType(ClaimEntity.class, true, true).values();
            for (ClaimEntity c : claims) {
                em.persist(c);
            }
            LOG.info(claims.size() + " ClaimEntity added");

            Collection<TrustedIdpEntity> trustedIdps = ctx.getBeansOfType(TrustedIdpEntity.class).values();
            for (TrustedIdpEntity t : trustedIdps) {
                em.persist(t);
            }
            LOG.info(trustedIdps.size() + " TrustedIdpEntity added");

            Collection<ApplicationEntity> applications = ctx.getBeansOfType(ApplicationEntity.class).values();
            for (ApplicationEntity a : applications) {
                em.persist(a);
            }
            LOG.info(applications.size() + " ApplicationEntity added");

            Collection<IdpEntity> idps = ctx.getBeansOfType(IdpEntity.class).values();
            for (IdpEntity i : idps) {
                em.persist(i);
            }
            LOG.info(idps.size() + " IdpEntity added");

            Collection<ApplicationClaimEntity> applicationClaims =
                ctx.getBeansOfType(ApplicationClaimEntity.class).values();
            for (ApplicationClaimEntity ac : applicationClaims) {
                em.persist(ac);
            }
            LOG.info(applicationClaims.size() + " ApplicationClaimEntity added");

            em.flush();
        } catch (Exception ex) {
            LOG.warn("Failed to initialize DB with data", ex);
        } finally {
            if (ctx != null) {
                ctx.close();
            }
        }
    }

}
