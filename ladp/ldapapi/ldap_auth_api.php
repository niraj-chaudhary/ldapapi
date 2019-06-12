<?php

error_reporting(!E_ALL);

if(isset($_POST['username']) && isset($_POST['password']))
{
	if (!empty($_POST['username'])&& !empty($_POST['password']))
    {
    	$user = $_POST['username'];
        $password = $_POST['password'];
    	$server = "10.30.73.14";
    	$dn = "ou=People,dc=shopclues,dc=com";
    	ldap_connect($server);
    	$con = ldap_connect($server);
    	ldap_set_option($con, LDAP_OPT_PROTOCOL_VERSION, 3);
    	$user_search = ldap_search($con,$dn,"(|(uid=$user)(mail=$user))");
    	$user_get = ldap_get_entries($con, $user_search);
    	$user_entry = ldap_first_entry($con, $user_search);
    	$user_dn = ldap_get_dn($con, $user_entry);

       	if (ldap_bind($con, $user_dn, $password) === true) {					
        	$dn2 = "dc=shopclues,dc=com";
    		$user_search2 = ldap_search($con,$dn2, "(&(cn=*)(memberUid=$user))");
    		$user_get2 = ldap_get_entries($con, $user_search2);
			$groups = array();
			foreach($user_get2 as $kn => $uobj) {
				$dn_temp = explode(",", $uobj["dn"]);
				$cn_temp = explode("=", $dn_temp[0]);
				if(!empty($cn_temp[1])){
					$groups[] = $cn_temp[1];
				}
			}
			echo json_encode(array("auth" => "YES", "groups" => $groups));
		} else{
			echo json_encode(array("auth" => "NO"));
    	}
	}
}

?>

