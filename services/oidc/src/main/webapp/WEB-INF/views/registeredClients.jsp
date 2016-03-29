<%@ page import="org.apache.cxf.rs.security.oauth2.common.Client"%>
<%@ page import="java.text.SimpleDateFormat"%>
<%@ page import="java.util.Collection"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.util.TimeZone"%>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="org.apache.cxf.fediz.service.oidc.clients.RegisteredClients" %>

<%
	Collection<Client> regs = ((RegisteredClients)request.getAttribute("data")).getClients();
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    } 
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Registered Clients</title>
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
<h1>Registered Clients</h1>
<br/>
<table border="1" id=registered_clients>
    <tr><th>Name</th><th>ID</th><th>Creation Date</th><th>Redirect URI</th></tr> 
    <%
       SimpleDateFormat dateFormat = new SimpleDateFormat("dd MMM yyyy", Locale.US);
       dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
               
       for (Client client : regs) {
    %>
       <tr>
           <td><a href="<%= basePath + "console/clients/" + client.getClientId() %>"><%= client.getApplicationName() %></a></td>
           <td>
              <%= client.getClientId() %>
           </td>
           <td>
           <% 
               Date date = new Date(client.getRegisteredAt() * 1000);
               String created = dateFormat.format(date);
		   %>
           <%=    created %><br/>
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
<a href="<%= basePath + "console/clients/register" %>">Register a new client</a>
</p>
</div>
</body>
</html>

