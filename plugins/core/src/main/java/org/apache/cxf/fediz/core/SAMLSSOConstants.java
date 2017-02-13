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

package org.apache.cxf.fediz.core;

/**
 * Constants specific to SAML SSO
 */
public final class SAMLSSOConstants extends FedizConstants {

    public static final String FEDIZ_SAML_METADATA_PATH_URI = "SAML/Metadata.xml";

    public static final String SAML_REQUEST = "SAMLRequest";

    public static final String SAML_RESPONSE = "SAMLResponse";

    public static final String RELAY_STATE = "RelayState";

    public static final String SIG_ALG = "SigAlg";

    public static final String SIGNATURE = "Signature";

    private SAMLSSOConstants() {
        super();
    }
}
