<%@ page import="org.apache.cxf.rs.security.oauth2.common.Client"%>
<%@ page import="org.apache.cxf.rs.security.oauth2.common.ServerAccessToken"%>
<%@ page import="org.apache.cxf.rs.security.oauth2.tokens.refresh.RefreshToken"%>
<%@ page import="java.text.SimpleDateFormat"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.List"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.util.TimeZone"%>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="org.apache.cxf.fediz.service.oidc.CSRFUtils" %>
<%@ page import="org.apache.cxf.fediz.service.oidc.clients.ClientTokens" %>
<%@ page import="org.owasp.esapi.ESAPI" %>

<%
	ClientTokens tokens = (ClientTokens)request.getAttribute("data");
	Client client = tokens.getClient();
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    } 
    SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss", Locale.US);
    dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    
    // Get or generate the CSRF token
    String csrfToken = CSRFUtils.getCSRFToken(request, true);
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Client Access Tokens</title>
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
<h1>Tokens issued to <%= ESAPI.encoder().encodeForHTML(client.getApplicationName()) + " (" + client.getClientId() + ")"%></h1>
<br/>
<div class="padded">
<h2>Access Tokens</h2>
<br/>
<table border="1">
    <tr>
       <th>ID</th><th>Issue Date</th><th>Expiry Date</th>
       <%
          if (!tokens.getRefreshTokens().isEmpty()) {
       %>
          <th>Refresh Token</th>
       <%
          }
       %>
       <%
          if (!tokens.getAccessTokens().isEmpty()) {
       %>
          <th>Action</th>
       <%
          }
       %>   
          
    </tr> 
    <%
       for (ServerAccessToken token : tokens.getAccessTokens()) {
    %>
       <tr>
           <td><%= token.getTokenKey() %></td>
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
           <%
	          if (!tokens.getRefreshTokens().isEmpty()) {
	       %>
	         <td>
	          <%
	          if (token.getRefreshToken() != null) {
	          %>
	           <%=    token.getRefreshToken() %>
	          <%
	            }
	          %> 
	         </td>
	       <%
	          }
	       %>
           <td>
               <form action="<%=basePath%>console/clients/<%= client.getClientId() + "/at/" + token.getTokenKey() + "/revoke"%>" method="POST">
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
<h2>Refresh Tokens</h2>
<br/>
<table border="1">
    <tr><th>ID</th><th>Issue Date</th><th>Expiry Date</th><th>Access Token</th> 
       <%
          if (!tokens.getRefreshTokens().isEmpty()) {
       %>
          <th>Action</th>
       <%
          }
       %>
    </tr>   
    <%
       for (RefreshToken token : tokens.getRefreshTokens()) {
    %>
       <tr>
           <td><%= token.getTokenKey() %></td>
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
           <%
	          for (String at : token.getAccessTokens()) {
	       %>
	           <%=    at %><br/>
	       <%
	          }
	       %>
           </td>    
	       
           <td>
               <form action="<%=basePath%>console/clients/<%= client.getClientId() + "/rt/" + token.getTokenKey() + "/revoke"%>" method="POST">
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

