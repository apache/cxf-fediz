<%@ page import="org.apache.cxf.rs.security.oauth2.common.Client"%>
<%@ page import="java.text.SimpleDateFormat"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.util.TimeZone"%>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="org.apache.cxf.fediz.service.oidc.CSRFUtils" %>
<%@ page import="org.apache.commons.text.StringEscapeUtils" %>

<%
	Client client = (Client)request.getAttribute("data");
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    }
    
    // Get or generate the CSRF token
    String token = CSRFUtils.getCSRFToken(request, true);
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>API Client Information</title>
    <link rel="stylesheet" href="<%= basePath %>static/styles.css">
</head>
<body>
<div class="padded">
<h1><a href="<%= basePath + "console/clients/" + client.getClientId() + "/edit" %>"><%= StringEscapeUtils.escapeHtml4(client.getApplicationName()) %></a></h1>
<br/>
<table border="1" id=client>
    <%
       SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm", Locale.US);
       dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    %>
    <tr><th>ID</th><th>Type</th><th>Secret</th><th>Creation Date</th></tr> 
       <tr>
           <td>
               <%= client.getClientId() %>
           </td>
           <td>
               <%= client.isConfidential() ? "Confidential" : "Public" %>
           </td> 
           <td>
           <%
              if (client.getClientSecret() != null) {
           %>
              <%= client.getClientSecret() %>
           <%
              } else {
           %>
              <i>Unavailable</i>
           <%
              } 
           %>
           </td>
           <td>
           <% 
               Date date = new Date(client.getRegisteredAt() * 1000);
               String created = dateFormat.format(date);
		   %>
           <%=    created %>
           
           </td>
           
       </tr>
     
</table>
<br/>
<h2>Restrictions:</h2>
<p/>
<table>
<tr>
<td>
<b>Home Realm</b>
</td>
<td>
<%  String homeRealmAlias = client.getProperties().get("homeRealmAlias");
    if (homeRealmAlias == null || homeRealmAlias.trim().isEmpty()) {
        homeRealmAlias = "Default - User selection at login";
    }
%> 
    <%=  homeRealmAlias %>
</td>
</tr>
<tr>
<td>
<b>Redirect URL</b>
</td>
<td>
<% if (client.getRedirectUris() != null) {
                for (String redirectURI : client.getRedirectUris()) {
		   %>
           <%=    redirectURI %><br/>
           <%   }
              } %>
</td>
</tr>
<tr>
<td>
<b>Audience URL</b>
</td>
<td>
<% if (client.getRegisteredAudiences() != null) {
                for (String audURI : client.getRegisteredAudiences()) {
		   %>
           <%=    audURI %><br/>
           <%   }
              } %>
</td>
</tr>
<tr>
<td>
<b>Logout URL</b>
</td>
<td>
<% if (client.getProperties().get("post_logout_redirect_uris") != null) { %>
           <%=    client.getProperties().get("post_logout_redirect_uris") %>
<% } %>
</td>
</tr>
</table>
<br/>
<p>
<p><a href="<%= basePath + "console/clients/" + client.getClientId() + "/tokens" %>">Issued Tokens</a></p>
</p>
<p>
<p><a href="<%= basePath + "console/clients/" + client.getClientId() + "/codes" %>">Issued Code Grants</a></p>
</p>

<br/>
<table class="table_no_border">
<tr>
<%
    if (client.getClientSecret() != null) {
%>
<td class="td_no_border">
<form name="resetSecretForm" action="<%=basePath%>console/clients/<%= client.getClientId() + "/reset"%>" method="POST">
    <div class="form-line">
        <input type="hidden" value="<%=token%>" name="client_csrfToken" />
    </div>
    <div data-type="control_button" class="form-line">
        <button name="submit_reset_button" class="form-submit-button" type="submit">Reset Client Secret</button>
    </div>
</form>
</td>
<%
    }
%>
<td class="td_no_border">
<form name="deleteForm" action="<%=basePath%>console/clients/<%= client.getClientId() + "/remove"%>" method="POST">
    <div class="form-line">
        <input type="hidden" value="<%=token%>" name="client_csrfToken" />
    </div>
    <div data-type="control_button" class="form-line">
       <button name="submit_delete_button" class="form-submit-button" type="submit">Delete Client</button>
    </div>
</form>
</td>
</tr>
</table>
<br/>

<p>
<p>Return to <a href="<%=basePath%>console/clients">registered Clients</a></p>
</p>
<br/>
</div>
</body>
</html>

