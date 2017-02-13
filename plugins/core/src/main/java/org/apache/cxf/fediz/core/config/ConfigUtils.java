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

import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.fediz.core.config.jaxb.ArgumentType;
import org.apache.cxf.fediz.core.config.jaxb.CallbackType;
import org.apache.cxf.fediz.core.util.ClassLoaderUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class ConfigUtils {
    
    private static final Logger LOG = LoggerFactory.getLogger(ConfigUtils.class);
    
    private ConfigUtils() {
        // complete
    }
    
    public static Object loadCallbackType(CallbackType cbt, String name, ClassLoader classLoader) {
        if (cbt == null || cbt.getValue() == null) {
            return null;
        }
        if (cbt.getType() == null || cbt.getType().equals(ArgumentType.STRING)) {
            return cbt.getValue();
        } else if (cbt.getType().equals(ArgumentType.CLASS)) {
            List<Object> handler = new ArrayList<>();
            String[] cbtHandler = cbt.getValue().split(",");
            for (String cbh : cbtHandler) {
                try {
                    if (classLoader == null) {
                        handler.add(ClassLoaderUtils.loadClass(cbh, ConfigUtils.class).newInstance());
                    } else {
                        handler.add(classLoader.loadClass(cbh).newInstance());
                    }
                } catch (Exception e) {
                    LOG.error("Failed to create instance of " + cbh, e);
                    //throw new IllegalStateException("Failed to create instance of " + cbt.getValue());
                }
            }
            if (handler.size() == 1) {
                // Backward compatible return handler directly if only one is configured
                return handler.get(0);
            } else {
                return handler;
            }
        } else {
            LOG.error("Only String and Class are supported for '{}'", name);
            throw new IllegalStateException("Only String and Class are supported for '" + name + "'");
        }
    }
}