<%@ page import="org.apache.cxf.rs.security.oauth2.common.Client"%>
<%@ page import="org.apache.cxf.rs.security.oauth2.common.ServerAccessToken"%>
<%@ page import="java.text.SimpleDateFormat"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.List"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.util.TimeZone"%>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="org.apache.cxf.fediz.service.oidc.ClientAccessTokens" %>

<%
	ClientAccessTokens tokens = (ClientAccessTokens)request.getAttribute("data");
	Client client = tokens.getClient();
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    } 
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
<div class="padded">
<h1>Access Tokens issued to <%= client.getApplicationName() + "(" + client.getClientId() + ")"%></h1>
<br/>
<table border="1">
    <tr><th>Identifier</th><th>Issue Date</th><th>Expiry Date</th></tr> 
    <%
       SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss", Locale.US);
       dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
               
       for (ServerAccessToken token : tokens.getAccessTokens()) {
    %>
       <tr>
           <td><input type="text" name="tokenId" size="15" readonly="readonly" value="<%= token.getTokenKey() %>" /></td>
           <td>
           <% 
               Date issuedDate = new Date(token.getIssuedAt() * 1000);
               String issued = dateFormat.format(issuedDate);
		   %>
           <%=    issued %><br/>
           </td>
           <td>
           <% 
               Date expiresDate = new Date((token.getIssuedAt() + token.getExpiresIn()) * 1000);
               String expires = dateFormat.format(expiresDate);
		   %>
           <%=    expires %><br/>
           </td>
           <td>
               <form action="/fediz-oidc/clients/<%= client.getClientId() + "/at/" + token.getTokenKey() + "/revoke"%>" method="POST">
		         <div data-type="control_button" class="form-line">
				   <button class="form-submit-button" type="submit">Delete</button>
		         </div>
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
<a href="<%= basePath + "clients/" + client.getClientId() %>">Return</a>
</p>
</div>
</body>
</html>

