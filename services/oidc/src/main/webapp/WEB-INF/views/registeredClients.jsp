<%@ page import="org.apache.cxf.rs.security.oauth2.common.Client"%>
<%@ page import="java.util.Collection"%>
<%@ page import="javax.servlet.http.HttpServletRequest" %>

<%
	Collection<Client> regs = (Collection<Client>)request.getAttribute("data");
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    } 
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>API Client Registration Confirmation</title>
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
	</STYLE>
</head>
<body>
<div class="padded">
<h1>Registered API Clients</h1>
<br/>
<table border="1">
    <tr><th>Client Name</th><th>Client Identifier</th><th>Client Secret</th><th>Redirect URIs</th></tr> 
    <%
       for (Client client : regs) {
    %>
       <tr>
           <td><%= client.getApplicationName() %></td>
           <td><input type="text" name="clientId" size="15" readonly="readonly" value="<%= client.getClientId() %>" /></td>
           <td>
           <%
              if (client.getClientSecret() != null) {
           %>
              <input type="text" name="clientSecret" size="25" readonly="readonly" value="<%= client.getClientSecret() %>" />
           <%
              } else {
           %>
              <i>Unavailable for public client</i>
           <%
              } 
           %>
           </td>
           <td>
           <% if(client.getRedirectUris() != null) {
                for (String redirectURI : client.getRedirectUris()) {
		   %>
           <%=    redirectURI %><br/>
           <%   }
              } %>
           </td>
       </tr>
    <%   
       }
    %> 
    
</table>

<br/>
<br/>
<p>
<a href="<%= basePath + "clients/register" %>">Register a new client</a>
</p>
</div>
</body>
</html>

