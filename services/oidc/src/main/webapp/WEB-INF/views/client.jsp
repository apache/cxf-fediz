<%@ page import="org.apache.cxf.rs.security.oauth2.common.Client"%>
<%@ page import="java.text.SimpleDateFormat"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.util.TimeZone"%>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="org.owasp.esapi.ESAPI" %>

<%
	Client client = (Client)request.getAttribute("data");
	String clientType = client.isConfidential() ? "Confidential" : "Public";
	String homeRealmAlias = client.getProperties().get("homeRealmAlias");
	if (homeRealmAlias == null || homeRealmAlias.trim().isEmpty()) {
	    homeRealmAlias = "Default - User selection at login";
	} 
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    } 
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>API Client Information</title>
    <STYLE TYPE="text/css">
    	table {
		    border-collapse: collapse;
		}
		table th {
		    background-color: #f0f0f0;
		    border-color: #ccc;
		    border-style: solid;
		    border-width: 1px;
                    padding: 3px 4px;
		    text-align: center;
		}
		table td {
		    border-color: #ccc;
		    border-style: solid;
                    border-width: 1px;
                    padding: 3px 4px;
		}



.table_no_border {
    border-collapse: collapse;
}
.table_no_border .td_no_border {
    padding: 0;
    border-width: 0px;
}


		
.form {
	max-width: 425px;
	margin-bottom: 25px;
	margin-left: auto;
	margin-right: auto;
}

.form-line {
	margin: 6 0 6 0;
	padding: 12 12 12 12;
}

.form-submit-button {
	padding: 4px;
	text-align: center;
}
		
	</STYLE>
</head>
<body>
<div class="padded">
<h1><%= ESAPI.encoder().encodeForHTML(client.getApplicationName()) %></h1>
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
               <%= clientType %>
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
           <%=    created %><br/>
           
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
     <div data-type="control_button" class="form-line">
	<button name="submit_reset_button" class="form-submit-button" type="submit">Reset Client Secret</button>
</form>
     </div> 
</td>
<%
    }
%>
<td class="td_no_border">
<form name="deleteForm" action="<%=basePath%>console/clients/<%= client.getClientId() + "/remove"%>" method="POST">
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

