<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="java.util.List" %>
<%@ page import="org.apache.cxf.rs.security.oauth2.common.OAuthAuthorizationData" %>
<%@ page import="org.apache.cxf.rs.security.oauth2.common.OAuthPermission" %>
<%@ page import="org.owasp.esapi.ESAPI" %>


<%
    OAuthAuthorizationData data = (OAuthAuthorizationData)request.getAttribute("data");
    List<String> authorizedScopes = data.getAlreadyAuthorizedPermissionsAsStrings();
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Third Party Authorization Form</title>
    <STYLE TYPE="text/css">
	<!--
	  input,button {font-family:verdana, arial, helvetica, sans-serif;font-size:20px;line-height:40px;} 
	-->
</STYLE>
</head>
<body>
<h1 align="center">Third Party Authorization Form</h1>
<table align="center">
       <tr align="center">
                <td>

                    <form action="<%= data.getReplyTo() %>" method="POST" onsubmit="prepareSubmit(this)">
                    
                        <input type="hidden" name="client_id"
                               value="<%= data.getClientId() %>"/>
                        <%
                            if (data.getState() != null) {
                        %>       
                        <input type="hidden" name="state"
                               value="<%= data.getState() %>"/>
                        <%
                            }
                        %>
                        <%
                            if (data.getClientCodeChallenge() != null) {
                        %>       
                        <input type="hidden" name="code_challenge"
                               value="<%= data.getClientCodeChallenge() %>"/>
                        <%
                            }
                        %>
                        <%
                            if (data.getNonce() != null) {
                        %>       
                        <input type="hidden" name="nonce"
                               value="<%= data.getNonce() %>"/>
                        <%
                            }
                        %>       
                        <input type="hidden" name="scope"
                               value="<%= data.getProposedScope() %>"/>
                        <input type="hidden" name="response_type"
                               value="<%= data.getResponseType() %>"/>
                        
                        <%
                            if (data.getRedirectUri() != null) {
                        %>       
                        <input type="hidden" name="redirect_uri"
                               value="<%= data.getRedirectUri() %>"/>
                        <%
                            }
                        %>                     
                        <input type="hidden"
                               name="<%= org.apache.cxf.rs.security.oauth2.utils.OAuthConstants
                                   .SESSION_AUTHENTICITY_TOKEN %>"
                               value="<%= data.getAuthenticityToken() %>"/>
						<%
                            if (data.getApplicationLogoUri() != null) {
                        %>                        
                        <img src="<%= data.getApplicationLogoUri() %>" alt="Application Logo" width="100" height="100">
                        <%
                            }
                        %>

                        <h2>Would you like to grant <%= ESAPI.encoder().encodeForHTML(data.getApplicationName()) %><br />the following permissions:</h2>

                        <table> 
                            <%
                               for (OAuthPermission perm : data.getAllPermissions()) {
                            %>
                               <tr>
                                <td>
                                  <input type="checkbox" 
                                    <%
                                      if (perm.isDefault() || authorizedScopes.contains(perm.getPermission())) {
                                    %>
                                    disabled="disabled"
                                    <%
                                      }
                                    %> 
                                    checked="checked"
                                    name="<%= perm.getPermission()%>_status" 
                                    value="allow"
                                  ><big><big><%= perm.getDescription() %></big></big></input>
                                    <%
                                      if (perm.isDefault()) {
                                    %>
                                    <input type="hidden" name="<%= perm.getPermission()%>_status" value="allow" />
                                    <%
                                      }
                                    %>
                                </td>
                               </tr>
                            <%   
                               }
                            %> 
                        </table>    
                        <br/></p>
                        <button name="<%= org.apache.cxf.rs.security.oauth2.utils.OAuthConstants
                            .AUTHORIZATION_DECISION_KEY %>"
                                type="submit"
                                value="<%= org.apache.cxf.rs.security.oauth2.utils.OAuthConstants
                                    .AUTHORIZATION_DECISION_ALLOW %>">
                            OK
                        </button>
                        <button name="<%= org.apache.cxf.rs.security.oauth2.utils.OAuthConstants
                            .AUTHORIZATION_DECISION_KEY %>"
                                type="submit"
                                value="<%= org.apache.cxf.rs.security.oauth2.utils.OAuthConstants
                                    .AUTHORIZATION_DECISION_DENY %>">
                            No,thanks
                        </button>
                    </form>
                </td>
            </tr>
        </table>
    
</body>
<script language="javascript">
    /**
     * Prepares the form for submission by appending any URI
     * fragment (hash) to the form action in order to propagate it
     * through the re-direct
     * @param form The login form object.
     * @returns true to allow the form to be submitted.
     */
    function prepareSubmit(form) {
        // Extract the fragment from the browser's current location.
        var hash = decodeURIComponent(self.document.location.hash);

        // The fragment value may not contain a leading # symbol
        if (hash && hash.indexOf("#") === -1) {
            hash = "#" + hash;
        }

        // Append the fragment to the current action so that it persists to the redirected URL.
        form.action = form.action + hash;
        return true;
    }
</script>
</html>
