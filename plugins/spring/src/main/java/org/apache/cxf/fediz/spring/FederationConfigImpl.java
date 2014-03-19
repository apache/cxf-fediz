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

package org.apache.cxf.fediz.spring;

import java.util.List;

import javax.servlet.ServletContext;

import org.apache.cxf.fediz.core.config.FederationConfigurator;
import org.apache.cxf.fediz.core.config.FederationContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.web.context.ServletContextAware;

public class FederationConfigImpl implements FederationConfig, ServletContextAware {

    private static final Logger LOG = LoggerFactory.getLogger(FederationConfigImpl.class);
    
    private Resource configFile;
    private String contextName;
    
    private ServletContext servletContext;
    private FederationConfigurator configurator = new FederationConfigurator();
    
    
    public Resource getConfigFile() {
        return configFile;
    }

    public void setConfigFile(Resource configFile) {
        this.configFile = configFile;
    }
    
    public String getContextName() {
        return contextName;
    }

    public void setContextName(String contextName) {
        this.contextName = contextName;
    }
    
    public void init() {
        Assert.notNull(this.configFile, "property 'configFile' mandatory");
        try {
            configurator.loadConfig(this.configFile.getFile());
        } catch (Exception e) {
            LOG.error("Failed to parse '" + configFile.getDescription() + "'", e);
            throw new BeanCreationException("Failed to parse '" + configFile.getDescription() + "'");
        }
    }

    @Override
    public List<FederationContext> getFederationContextList() {
        return configurator.getFederationContextList();
    }

    @Override
    public FederationContext getFederationContext(String context) {
        FederationContext ctx = configurator.getFederationContext(context);
        if (ctx == null) {
            LOG.error("Federation context '" + context + "' not found.");
            throw new IllegalStateException("Federation context '" + context + "' not found.");
        }
        return ctx;
    }

    @Override
    public FederationContext getFederationContext() {
        if (servletContext != null) {
            LOG.debug("Reading federation configuration for context '{}'",
                      servletContext.getContextPath());
            return getFederationContext(servletContext.getContextPath());
        } else {
            Assert.notNull(contextName, "Property 'contextName' must be configured because ServletContext null");
            return getFederationContext(contextName);
        }
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

}
