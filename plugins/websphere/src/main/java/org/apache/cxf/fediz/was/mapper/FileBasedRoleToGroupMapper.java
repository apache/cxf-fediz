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
package org.apache.cxf.fediz.was.mapper;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.apache.cxf.fediz.was.mapping.config.Mapping;
import org.apache.cxf.fediz.was.mapping.config.SamlToJ2EE;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reference implementation for a Federation Claim to local WAS Group Mapper
 */
public class FileBasedRoleToGroupMapper implements RoleToGroupMapper {

    /**
     * This constant contains the name for the property to discover the role mapping file refresh rate. The value of
     * this property contains the number of seconds to wait, before changes in the file are detected and applied.
     */
    public static final String PROPERTY_KEY_ROLE_MAPPING_REFRESH_TIMEOUT = "roleMappingRefreshTimeout";
    /**
     * This constant contains the name for the property to discover the location of the role to group mapping file.
     */
    public static final String PROPERTY_KEY_ROLE_MAPPING_LOCATION = "roleMappingLocation";

    /**
     * @deprecated Use PROPERTY_KEY_ROLE_MAPPING_REFRESH_TIMEOUT instead.
     */
    @Deprecated
    private static final String REFRESH_TIMEOUT_PARAMETER = "groups.mapping.refresh.timeout";
    /**
     * @deprecated Use PROPERTY_KEY_ROLE_MAPPING_LOCATION instead.
     */
    @Deprecated
    private static final String MAPPING_FILE_PARAMETER = "groups.mapping.file";

    private static final String INITIALIZATION_THREAD_NAME = "ClaimGroupMapper";

    private static final Logger LOG = LoggerFactory.getLogger(FileBasedRoleToGroupMapper.class);

    private String groupMappingFilename = "./mapping.xml";
    private int refreshRateMillisec = 30 * 1000;
    private boolean doLoop = true;
    private Map<String, List<String>> mappings = new HashMap<>(10);
    private long mappingFileLastModificationDate = -1;

    @Override
    public List<String> groupsFromRoles(List<String> roles) {
        if (roles == null) {
            return null;
        }

        List<String> groups = new ArrayList<>(20);
        for (String key : roles) {
            List<String> groupList = mappings.get(key);
            if (groupList != null) {
                groups.addAll(groupList);
            } else {
                LOG.debug("missing group for role: {}", key);
            }
        }
        return groups;
    }

    @Override
    public void initialize(Properties props) {
        if (props != null) {
            String fileLocation = props.containsKey(PROPERTY_KEY_ROLE_MAPPING_LOCATION)
                    ? props.getProperty(PROPERTY_KEY_ROLE_MAPPING_LOCATION)
                    : props.getProperty(MAPPING_FILE_PARAMETER);
            if (fileLocation != null) {
                groupMappingFilename = fileLocation;
                LOG.info("Mapping file set to {}", fileLocation);
            }
            String timeout = props.containsKey(PROPERTY_KEY_ROLE_MAPPING_REFRESH_TIMEOUT)
                    ? props.getProperty(PROPERTY_KEY_ROLE_MAPPING_REFRESH_TIMEOUT)
                    : props.getProperty(REFRESH_TIMEOUT_PARAMETER);
            if (timeout != null) {
                refreshRateMillisec = Integer.parseInt(timeout) * 1000;
                LOG.info("Mapping file refresh timeout (sec) set to {}", timeout);
            }
        }

        // start the internal initialization thread
        Thread initializationThread = new Thread() {
            @Override
            public void run() {
                while (doLoop) {
                    internalInit();
                    try {
                        sleep(refreshRateMillisec);
                    } catch (InterruptedException e) {
                        // nothing we can do here
                    }
                }
            }
        };
        initializationThread.setName(INITIALIZATION_THREAD_NAME);
        initializationThread.setPriority(Thread.MIN_PRIORITY);
        initializationThread.start();
        LOG.info("Mapping file refresher thread started");
    }

    private void internalInit() {
        synchronized (mappings) {
            try {
                File mappingFile = new File(groupMappingFilename);
                if (!mappingFile.exists()) {
                    throw new FileNotFoundException(groupMappingFilename);
                }
                boolean update = false;
                if (mappings.isEmpty()) {
                    mappingFileLastModificationDate = mappingFile.lastModified();
                    update = true;
                } else {
                    long currentFileModificationDate = mappingFile.lastModified();
                    if (currentFileModificationDate > mappingFileLastModificationDate) {
                        update = true;
                        mappingFileLastModificationDate = currentFileModificationDate;
                    }
                }
                if (update) {
                    LOG.info("Mapping file has changed. Reloading...");
                    Map<String, List<String>> newMap = loadMappingFile();

                    mappings.clear();
                    mappings.putAll(newMap);
                    LOG.info("Mapping file reloaded.");
                }
            } catch (IOException e) {
                LOG.warn("Unable to load mappings due to: " + e.getMessage());
            } catch (JAXBException e) {
                LOG.warn("Unable to parse mappings due to: " + e.getMessage());
            }
        }
    }

    private Map<String, List<String>> loadMappingFile() throws JAXBException, IOException {
        Map<String, List<String>> map = new HashMap<>(10);

        try (InputStream input = new FileInputStream(groupMappingFilename)) {
            JAXBContext context = JAXBContext.newInstance(Mapping.class);
            Mapping localmappings = (Mapping) context.createUnmarshaller().unmarshal(input);

            Iterator<SamlToJ2EE> i = localmappings.getSamlToJ2EE().iterator();
            while (i.hasNext()) {
                SamlToJ2EE mapping = i.next();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("{} mapped to {} entries", mapping.getClaim(), mapping.getGroups().getJ2EeGroup().size());
                }
                map.put(mapping.getClaim(), mapping.getGroups().getJ2EeGroup());
            }
        }

        return map;
    }

    @Override
    public void cleanup() {
        LOG.info("Stopping the mapping file refresher loop");
        doLoop = false;
    }

}
