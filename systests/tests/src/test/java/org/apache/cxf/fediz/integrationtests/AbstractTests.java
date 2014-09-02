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

package org.apache.cxf.fediz.integrationtests;

import org.apache.cxf.fediz.core.ClaimTypes;
import org.junit.Assert;

public abstract class AbstractTests {

    public AbstractTests() {
        super();
    }

    public abstract String getServletContextName();
    
    public abstract String getIdpHttpsPort();

    public abstract String getRpHttpsPort();

    @org.junit.Test
    public void testAlice() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "ecila";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=false") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=false") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Alice'",
                          response.indexOf(claim + "=Alice") > 0);
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Smith'",
                          response.indexOf(claim + "=Smith") > 0);
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'alice@realma.org'",
                          response.indexOf(claim + "=alice@realma.org") > 0);

    }
    
    @org.junit.Test
    public void testAliceUser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "alice";
        String password = "ecila";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=false") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=false") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);
    }
    
    @org.junit.Test
    public void testAliceAdminNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "alice";
        String password = "ecila";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));        
    }
    
    @org.junit.Test
    public void testliceManagerNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "alice";
        String password = "ecila";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));        
    }

    @org.junit.Test
    public void testAliceWrongPasswordNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "alice";
        String password = "alice";
        // sendHttpGet(url, user, password, 500, 0);        
        //[FIXED] Fix IDP return code from 500 to 401
        HTTPTestUtils.sendHttpGet(url, user, password, 401, 0, Integer.parseInt(getIdpHttpsPort()));        
    }

    @org.junit.Test
    public void testBob() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=true") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=true") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Bob'",
                          response.indexOf(claim + "=Bob") > 0);
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Windsor'",
                          response.indexOf(claim + "=Windsor") > 0);
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'bobwindsor@realma.org'",
                          response.indexOf(claim + "=bobwindsor@realma.org") > 0);
    }
    
    @org.junit.Test
    public void testBobUser() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=true") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=true") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);
    }
    
    @org.junit.Test
    public void testBobManager() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=true") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=true") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);
    }
    
    @org.junit.Test
    public void testBobAdmin() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "bob";
        String password = "bob";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=true") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=true") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=true") > 0);
    }

    @org.junit.Test
    public void testTed() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/fedservlet";
        String user = "ted";
        String password = "det";
        String response = 
            HTTPTestUtils.sendHttpGet(url, user, password, Integer.parseInt(getIdpHttpsPort()));

        Assert.assertTrue("Principal not " + user, response.indexOf("userPrincipal=" + user) > 0);
        Assert.assertTrue("User " + user + " does not have role Admin", response.indexOf("role:Admin=false") > 0);
        Assert.assertTrue("User " + user + " does not have role Manager", response.indexOf("role:Manager=false") > 0);
        Assert.assertTrue("User " + user + " must have role User", response.indexOf("role:User=false") > 0);

        String claim = ClaimTypes.FIRSTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Ted'",
                          response.indexOf(claim + "=Ted") > 0);
        claim = ClaimTypes.LASTNAME.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'Cooper'",
                          response.indexOf(claim + "=Cooper") > 0);
        claim = ClaimTypes.EMAILADDRESS.toString();
        Assert.assertTrue("User " + user + " claim " + claim + " is not 'tcooper@realma.org'",
                          response.indexOf(claim + "=tcooper@realma.org") > 0);
    }
    
    @org.junit.Test
    public void testTedUserNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/user/fedservlet";
        String user = "ted";
        String password = "det";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));
    }

    @org.junit.Test
    public void testTedAdminNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/admin/fedservlet";
        String user = "ted";
        String password = "det";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));        
    }
    
    @org.junit.Test
    public void testTedManagerNoAccess() throws Exception {
        String url = "https://localhost:" + getRpHttpsPort() + "/fedizhelloworld/secure/manager/fedservlet";
        String user = "ted";
        String password = "det";
        HTTPTestUtils.sendHttpGet(url, user, password, 200, 403, Integer.parseInt(getIdpHttpsPort()));        
    }

}
