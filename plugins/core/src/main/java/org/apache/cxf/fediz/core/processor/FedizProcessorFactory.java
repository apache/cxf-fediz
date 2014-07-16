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

package org.apache.cxf.fediz.core.processor;

import org.apache.cxf.fediz.core.config.FederationProtocol;
import org.apache.cxf.fediz.core.config.Protocol;
import org.apache.cxf.fediz.core.config.SAMLProtocol;

/**
 * A Factory to return FedizProcessor instances depending on the Protocol
 */
public final class FedizProcessorFactory {
    
    private FedizProcessorFactory() {
        // complete
    }

    public static FedizProcessor newFedizProcessor(Protocol protocol) {
        if (protocol instanceof FederationProtocol) {
            return new FederationProcessorImpl();
        } else if (protocol instanceof SAMLProtocol) {
            return new SAMLProcessorImpl();
        }
        return null;
    }

}
