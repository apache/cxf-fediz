<html>
<head><title>Delegate authenticated identity to web service</title></head>
<body>

<h1>Hello World</h1>
<p>Request url: <%= request.getRequestURL() %></p>
<br><b>User: <%= request.getUserPrincipal().getName() %></b></br>

<br>

<form action="fedservlet" method="POST">
    <input type="SUBMIT" value="Call Service">
</form>

</br>
</body>
</html>
