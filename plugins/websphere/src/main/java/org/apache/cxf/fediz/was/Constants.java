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
package org.apache.cxf.fediz.was;


/**
 * Constants used by the FedizInterceptor or SecurityContextTTLChecker classes
 */
//CHECKSTYLE:OFF
public interface Constants {
    
    String HTTP_POST_METHOD = "POST";
    //String UTF_8_ENCODING_SCHEME = "UTF-8";
    String VERSION = "1.2.0";
    String TIMESTAMP_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    
    String USER_REGISTRY_JNDI_NAME = "UserRegistry";

    String SUBJECT_TOKEN_KEY = "_security.token";
    String SUBJECT_SESSION_ATTRIBUTE_KEY = "_tai.subject";
    String SECURITY_TOKEN_SESSION_ATTRIBUTE_KEY = "fediz.security.token";

    /**
     * @deprecated Use FEDIZ_CONFIG_LOCATION instead.
     *
     * Using this property causes problems on Websphere 8.5. See https://issues.apache.org/jira/browse/FEDIZ-97 for more
     * details.
     */
    @Deprecated
    String CONFIGURATION_FILE_PARAMETER = "config.file.location";
    /**
     * This constant contains the name for the property to discover the location of the fediz configuration file.
     */
    String FEDIZ_CONFIG_LOCATION = "fedizConfigLocation";

    /**
     * @deprecated Use FEDIZ_ROLE_MAPPER instead.
     */
    @Deprecated
    String ROLE_GROUP_MAPPER = "role.group.mapper";

    /**
     * This constant contains the name for the property to discover the class-name which should be used for role to
     * group mappings.
     */
    String FEDIZ_ROLE_MAPPER = "fedizRoleMapper";
}
