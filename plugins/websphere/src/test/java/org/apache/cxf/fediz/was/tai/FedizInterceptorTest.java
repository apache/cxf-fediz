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

package org.apache.cxf.fediz.was.tai;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import com.ibm.websphere.security.WebTrustAssociationFailedException;

import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.was.Constants;
import org.easymock.EasyMock;
import org.junit.Test;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class FedizInterceptorTest {


    @Test
    public void testGroupMappingWithNull() throws WebTrustAssociationFailedException {

        FedizResponse resp = EasyMock.createMock(FedizResponse.class);
        EasyMock.expect(resp.getRoles()).andReturn(null);
        EasyMock.expect(resp.getUsername()).andReturn("Test-User").anyTimes();
        EasyMock.replay(resp);

        FedizInterceptor fedizInterceptor = new FedizInterceptor();
        Properties properties = new Properties();
        properties.put(Constants.PROPERTY_KEY_CONFIG_LOCATION, "src/test/resources/fediz_config.xml");
        fedizInterceptor.initialize(properties);
        List<String> result = fedizInterceptor.groupIdsFromTokenRoles(resp);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    public void testDirectGroupMapping() throws WebTrustAssociationFailedException {

        FedizResponse resp = EasyMock.createMock(FedizResponse.class);
        EasyMock.expect(resp.getRoles()).andReturn(Arrays.asList("Admin", "Manager"));
        EasyMock.expect(resp.getUsername()).andReturn("Test-User").anyTimes();
        EasyMock.replay(resp);

        FedizInterceptor fedizInterceptor = new FedizInterceptor();
        Properties properties = new Properties();
        properties.put(Constants.PROPERTY_KEY_CONFIG_LOCATION, "src/test/resources/fediz_config.xml");
        properties.put(Constants.PROPERTY_KEY_DIRECT_GROUP_MAPPING, "true");

        fedizInterceptor.initialize(properties);
        List<String> result = fedizInterceptor.groupIdsFromTokenRoles(resp);
        assertNotNull(result);
        assertEquals(2, result.size());
    }
}
