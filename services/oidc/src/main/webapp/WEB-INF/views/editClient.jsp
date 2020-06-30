<%@ page
	import="javax.servlet.http.HttpServletRequest, java.util.Map, org.apache.cxf.fediz.service.oidc.clients.EditClient,
        org.apache.cxf.rs.security.oauth2.common.Client, org.apache.cxf.fediz.service.oidc.CSRFUtils"
%>
<%
    EditClient editClient = (EditClient)request.getAttribute("data");
    Client c = editClient.getClient();
    String basePath = request.getContextPath() + request.getServletPath();
    if (!basePath.endsWith("/")) {
        basePath += "/";
    }

    // Get or generate the CSRF token
    String csrfToken = CSRFUtils.getCSRFToken(request, true);
%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Client Registration Form</title>
    <link rel="stylesheet" href="<%= basePath %>static/styles.css">
</head>
<body>
	<form action="<%= basePath + "console/clients/" + c.getClientId() %>" method="POST">
		<div class="form">
			<div class="header-text">
				<h2>OIDC Client Modification</h2>
			</div>
			<div class="form-line">
				<label for="client_name" id="label_name" class="form-label"> Name </label>
				<input placeholder="OIDC Client Name" type="text" value="<%=c.getApplicationName()%>"
					size="40" name="client_name" id="input_name" data-type="input-textbox" />
			</div>
			<div class="form-line">
				<label for="client_type" id="label_type" class="form-label"> Type </label>
				<select name="client_type" id="input_type" disabled="true">
					<option selected="selected"><%= c.isConfidential() ? "Confidential" : "Public" %></option>
				</select>
			</div>
			<div class="form-line">
				<label for="client_redirectURI" id="label_redirect" class="form-label"> Redirect URL </label>
				<input type="text" value="<%= c.getRedirectUris() != null ? String.join(" ", c.getRedirectUris()) : "" %>" size="40" name="client_redirectURI"
					placeholder="URL of the client to consume OIDC service response"
					id="input_6" data-type="input-textbox" />
			</div>
			<div class="form-line">
				<label for="client_audience" id="label_audience" class="form-label"> Audience URL </label>
				<input type="text" value="<%= c.getRegisteredAudiences() != null ? String.join(" ", c.getRegisteredAudiences()) : "" %>" size="40" name="client_audience"
					placeholder="URL of the server the tokens will be restricted to"
					id="input_7" data-type="input-textbox" />
			</div>
			<div class="form-line">
				<label for="client_logoutURI" id="label_logout" class="form-label"> Logout URL </label>
				<input type="text" value="<%= c.getProperties().get("post_logout_redirect_uris") != null ? c.getProperties().get("post_logout_redirect_uris") : "" %>" size="40" name="client_logoutURI"
					placeholder="URL of the client to finalize OIDC logout process"
					id="input_6" data-type="input-textbox" />
			</div>
			<div class="form-line">
				<label for="client_homeRealm" id="label_homeRealm" class="form-label"> Home Realm </label>
				<select name="client_homeRealm" id="input_homeRealm">
					<option value="" <%= c.getHomeRealm().isEmpty() ? "selected=\"selected\"" : "" %>>Default - User selection at login</option>
					<%
                        for (Map.Entry<String, String> entry : editClient.getHomeRealms().entrySet()) {
					%>
					<option value="<%=entry.getKey()%>" <%= c.getHomeRealm().equals(entry.getKey()) ? "selected=\"selected\"" : "" %>><%=entry.getValue()%></option>
					<%
                        }
					%>
				</select>
			</div>
			<div class="form-line">
				<input type="hidden" value="<%=csrfToken%>" name="client_csrfToken" />
			</div>
			<div data-type="control_button" class="form-line">
				<button name="submit_button" class="form-submit-button" type="submit">Update API Client</button>
			</div>
		</div>
	</form>
	<p>Return to <a href="<%= basePath + "console/clients/" + c.getClientId() %>">Client details</a></p>
</body>
</html>
