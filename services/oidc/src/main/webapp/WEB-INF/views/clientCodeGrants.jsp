<%@ page import="org.apache.cxf.rs.security.oauth2.common.Client"%>
<%@ page import="org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant"%>
<%@ page import="java.text.SimpleDateFormat"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.List"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.util.TimeZone"%>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="org.apache.cxf.fediz.service.oidc.CSRFUtils" %>
<%@ page import="org.apache.cxf.fediz.service.oidc.clients.ClientCodeGrants" %>
<%@ page import="org.owasp.esapi.ESAPI" %>

<%
	ClientCodeGrants tokens = (ClientCodeGrants)request.getAttribute("data");
	Client client = tokens.getClient();
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    }
    
    // Get or generate the CSRF token
    String csrfToken = CSRFUtils.getCSRFToken(request, true);
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Client Refresh Tokens</title>
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
<h1>Code Grants issued to <%= ESAPI.encoder().encodeForHTML(client.getApplicationName()) + " (" + client.getClientId() + ")"%></h1>
<br/>
<table border="1">
    <tr><th>ID</th><th>Issue Date</th><th>Expiry Date</th><th>Action</th></tr> 
    <%
       SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss", Locale.US);
       dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
               
       for (ServerAuthorizationCodeGrant token : tokens.getCodeGrants()) {
    %>
       <tr>
           <td><%= token.getCode() %></td>
           <td>
           <% 
               Date issuedDate = new Date(token.getIssuedAt() * 1000);
               String issued = dateFormat.format(issuedDate);
		   %>
           <%=    issued %><br/>
           </td>
           <%
		       if (token.getExpiresIn() > 0) {
		           Date expiresDate = new Date((token.getIssuedAt() + token.getExpiresIn()) * 1000);
                   String expires = dateFormat.format(expiresDate);
		   %>
           <td><%=    expires %></td>
           <%
		       } else {
		   %>
		   <td>Never</td>   
		   <%
		       }
		   %>
           <td>
               <form action="<%=basePath%>console/clients/<%= client.getClientId() + "/codes/" + token.getCode() + "/revoke"%>" method="POST">
                 <input type="hidden" value="<%=csrfToken%>" name="client_csrfToken" />
		         <input type="submit" value="Delete"/>
               </form>
           </td>
       </tr>
    <%   
       }
    %> 
    
</table>

<br/>
<br/>
<p>
<a href="<%= basePath + "console/clients/" + client.getClientId() %>">Return</a>
</p>
</div>
</body>
</html>

