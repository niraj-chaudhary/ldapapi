
jQuery(document).ready(function() {

    /*
        Fullscreen background
    */
    // $.backstretch("/static/img/backgrounds/1.jpg");

    /*
        Form validation
    */
    $('.login-form input[type="text"], .login-form input[type="password"], .login-form textarea').on('focus', function() {
    	$(this).removeClass('input-error');
    });

    $('.login-form').on('submit', function(e) {

    	$(this).find('input[type="text"], input[type="password"], textarea').each(function(){
    		if( $(this).val() == "" ) {
    			e.preventDefault();
    			$(this).addClass('input-error');
    		}
    		else {
    			$(this).removeClass('input-error');
    		}
    	});

    });
});

$("#Resend-otp").click(function(e) {
    $.ajax({
        type: "POST",
        url: "http://ldap.shopclues.com/password/otp",
        data: {
            empID: $("#new-pwd").val()
        },
        success: function(result) {
            $('#otp-haseen-sent').css('display','block');
        },
        error: function(result) {
        }
    });
});