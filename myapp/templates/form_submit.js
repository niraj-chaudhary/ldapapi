
String myvar = "<html>"+
"    <head>"+
"        <title>Add User In LDAP</title>"+
"        <link rel=stylesheet type=text/css href=\"{{ url_for('static', filename='style.css') }}\">"+
"	<link rel=stylesheet type=text/css href=\"{{ url_for('static', filename='style_1.css') }}\">"+
"    </head>"+
"	<header>"+
"        <div class=\"logo_inner\"><img src=\"http://cdn02.example.net/images/ui/example-logo_new.jpg\" width=\"100%\" alt=\"\"/></div>"+
"        </div></header>"+
"    <body>"+
"        <div id=\"container\">"+
"            <div class=\"title\">"+
"                <h1>Request For User Add</h1><h1 align=\"right\"><a href='/logout'>Logout</a></h1>"+
"            </div>"+
"<section class=\"con_area clearfix\">"+
"  <div class=\"content\">"+
"    <div class=\"tabs\">"+
"      <ul>"+
"        <li class=\"active\"><a href=\"/addu\">Add User</a></li>"+
"        <li ><a href=\"cpw\">Change Password</a></li>"+
"      </ul>"+
"    </div>"+
"</div>"+
"</section>"+
"            <div id=\"content\">"+
"                <form method=\"post\" action=\"{{ url_for('adduser') }}\">"+
"	<h3>ex: If Email id is niraj.kumar@example.com then user name will niraj.kumar</h3></Br>"+
"                  <label for=\"username\">Please enter User Name:</label>"+
"                  <input type=\"text\" name=\"username\" /><br />"+
"                  <label for=\"empid\">Please enter your empid:</label>"+
"                  <input type=\"text\" name=\"empid\" /><br />"+
"                  <label for=\"mobileno\">Please enter your Mobile No:</label>"+
"                  <input type=\"text\" name=\"mobileno\" /><br />"+
"                  <label for=\"email\">Please enter your Email ID:</label>"+
"                  <input type=\"text\" name=\"email\" /><br />"+
"                  <label for=\"password\">Please enter your password:</label>"+
"                  <input type=\"password\" name=\"password\"/><br />"+
"		  <select name=\"group\">"+
"		  <option value=\"sasuser\">SASUSER</option>"+
"		  <option value=\"jira_users\">Jira User</option>"+
"		  </select>"+
"                  <input type=\"submit\" />"+
"                </form>"+
"            </div>"+
"            <div class=\"title\">"+
"                <h1>example.com</h1>"+
"            </div>"+
"            </div>"+
"        </div>"+
"    </body>"+
"</html>";
	

