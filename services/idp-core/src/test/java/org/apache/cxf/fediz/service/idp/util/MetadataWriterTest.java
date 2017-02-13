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

package org.apache.cxf.fediz.service.idp.util;

import org.w3c.dom.Document;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.metadata.IdpMetadataWriter;
import org.apache.cxf.fediz.service.idp.service.ConfigService;
import org.apache.wss4j.common.util.DOM2Writer;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.util.Assert;

public class MetadataWriterTest {

    private static ApplicationContext applicationContext;

    @BeforeClass
    public static void init() {
        applicationContext = new ClassPathXmlApplicationContext("/idp-config.xml");
    }

    @Test
    public void testWriteIDPMetadata() {
        ConfigService config = (ConfigService)applicationContext.getBean("config");
        Assert.notNull(config, "ConfigService must not be null");
        Idp idpConfig = config.getIDP("urn:org:apache:cxf:fediz:idp:realm-A");
        Assert.notNull(idpConfig, "IDPConfig must not be null");

        IdpMetadataWriter writer = new IdpMetadataWriter();
        Document doc = writer.getMetaData(idpConfig);
        Assert.notNull(doc, "doc must not be null");

        System.out.println(DOM2Writer.nodeToString(doc));

    }

}
