<%@ page import="org.apache.cxf.rs.security.oauth2.common.Client"%>
<%@ page import="java.text.SimpleDateFormat"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.util.TimeZone"%>
<%@ page import="javax.servlet.http.HttpServletRequest" %>

<%
	Client client = (Client)request.getAttribute("data");
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
	padding: 12 36 12 36;
}

.form-submit-button {
	padding: 4px;
	text-align: center;
}
		
	</STYLE>
</head>
<body>
<div class="padded">
<h1><%= client.getApplicationName() %></h1>
<br/>
<table border="1">
    <%
       SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm", Locale.US);
       dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    %>
    <tr><th>ID</th><th>Secret</th><th>Creation Date</th><th>Redirect URI</th></tr> 
       <tr>
           <td>
               <%= client.getClientId() %>
           <td>
           <%
              if (client.getClientSecret() != null) {
           %>
              <%= client.getClientSecret() %>
           <%
              } else {
           %>
              <i>Unavailable for public client</i>
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
           <td>
           <% if(client.getRedirectUris() != null) {
                for (String redirectURI : client.getRedirectUris()) {
		   %>
           <%=    redirectURI %><br/>
           <%   }
              } %>
           </td>
       </tr>
     
</table>
<br/>
<table class="table_no_border">
<tr>
<%
    if (client.getClientSecret() != null) {
%>
<td class="td_no_border">
<form action="/fediz-oidc/clients/<%= client.getClientId() + "/reset"%>" method="POST">
		<div data-type="control_button" class="form-line">
				<button class="form-submit-button" type="submit">Reset Secret</button>
		</div>
</form>
</td>
<%
    }
%>
<td class="td_no_border">
<form action="/fediz-oidc/clients/<%= client.getClientId() + "/remove"%>" method="POST">
		<div data-type="control_button" class="form-line">
				<button class="form-submit-button" type="submit">Delete Client</button>
		</div>
</form>
</td>
</tr>
</table>
<br/>
<p>
<p><a href="<%= basePath + "clients/" + client.getClientId() + "/tokens" %>">Issued Tokens</a></p>
</p>
<p>
<p><a href="<%= basePath + "clients/" + client.getClientId() + "/codes" %>">Issued Code Grants</a></p>
</p>
<br/>
<p>
<p>Return to <a href="<%=basePath%>clients">registered Clients</a></p>
</p>
<br/>
</div>
</body>
</html>

