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

package org.apache.cxf.fediz.core.config;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.apache.cxf.fediz.core.config.jaxb.ContextConfig;
import org.apache.cxf.fediz.core.config.jaxb.FedizConfig;

public class FedizConfigurator {

    private FedizConfig rootConfig;

    private JAXBContext jaxbContext;

    private List<FedizContext> fedizContextList;

    public FedizConfig loadConfig(File f) throws JAXBException, IOException {
        try (InputStream input = Files.newInputStream(f.toPath())) {
            rootConfig = (FedizConfig) getJaxbContext().createUnmarshaller().unmarshal(input);
        }
        parseFedizContextList();
        return rootConfig;
    }

    public FedizConfig loadConfig(Reader reader) throws JAXBException {
        rootConfig = (FedizConfig) getJaxbContext().createUnmarshaller().unmarshal(reader);
        parseFedizContextList();
        return rootConfig;
    }

    private void parseFedizContextList() {
        fedizContextList = new ArrayList<>();
        for (ContextConfig config : rootConfig.getContextConfig()) {
            fedizContextList.add(new FedizContext(config));
        }
    }

    public void saveConfiguration(File f) throws JAXBException {
        if (f.canWrite()) {
            jaxbContext.createMarshaller().marshal(rootConfig, f);
        }
    }

    public void saveConfiguration(Writer writer) throws JAXBException {
        jaxbContext.createMarshaller().marshal(rootConfig, writer);
    }

    private JAXBContext getJaxbContext() throws JAXBException {
        if (jaxbContext == null) {
            jaxbContext = JAXBContext.newInstance(FedizConfig.class);
        }
        return jaxbContext;
    }

    public List<FedizContext> getFedizContextList() {
        return fedizContextList;
    }

    public FedizContext getFedizContext(String contextName) {
        if (contextName == null) {
            throw new IllegalArgumentException("Context Name cannot be 'null'.");
        }
        if (contextName.isEmpty()) {
            contextName = "/";
        }
        if (rootConfig == null) {
            throw new IllegalArgumentException("No configuration loaded");
        }
        for (FedizContext fedContext : fedizContextList) {
            if (fedContext.getName().equals(contextName)) {
                fedContext.init();
                return fedContext;
            }
        }

        return null;
    }

    public ContextConfig getContextConfig(String contextName) {
        if (contextName == null) {
            throw new IllegalArgumentException("Context Name cannot be 'null'.");
        }
        if (contextName.isEmpty()) {
            contextName = "/";
        }
        if (rootConfig == null) {
            throw new IllegalArgumentException("No configuration loaded");
        }

        for (ContextConfig config : rootConfig.getContextConfig()) {
            if (contextName.equals(config.getName())) {
                return config;
            }
        }
        return null;
    }

}
