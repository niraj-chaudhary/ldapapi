import hashlib
import pyotp
import urllib2
import urllib
import re
from flask import Flask, render_template, request, flash, url_for, redirect
from ldap_helper import LDAPHelper
from utils import get_formatted_time
from flask_redis import FlaskRedis
from flask_mail import Mail, Message

app = Flask(__name__)
app.config.from_pyfile("dev.cfg")

mail = Mail(app)
redis_store = FlaskRedis(app)
ldhelper = LDAPHelper(app)


def validate_pwd(password):

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    print len(password)
    length_error = not (len(password) >= 8)

    # searching for symbols
    # symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error)

    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error
    }


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
        # render form here
        return render_template("index.html")
    elif request.method == "POST":
        empID = request.form.get('empID')
        result = ldhelper.search_user_by_uid(empID)
        msgs = []
        if result:
            cn = result[0][1]['cn'][0]
            if ldhelper.verify_password(cn, request.form.get('curPwd')):
                # Get new password and repeat password
                newPwd = request.form.get("newPwd", None)
                newPwdAgain = request.form.get('newPwdAgain', None)

                # Validation
                if newPwd and newPwdAgain:
                    if newPwd == newPwdAgain:
                        print validate_pwd(newPwd)
                        if validate_pwd(newPwd).get('password_ok') is True:
                            # Add additional validation
                            if ldhelper.change_password(cn, newPwd):
                                msgs.append({
                                    "class": "success",
                                    "body": "Password changed successfully"
                                })
                            else:
                                msgs.append({
                                    "class": "danger",
                                    "body": "Failed to change password"
                                })
                        else:
                            msgs.append({
                                "class": "danger",
                                "body": "Password Validation condition does not satisfied"
                            })
                    else:
                        msgs.append({
                            "class": "danger",
                            "body": "Passwords do not match"
                        })
                else:
                    msgs.append({
                        "class": "danger",
                        "body": "Password and Repeat password are empty"
                    })
            else:
                msgs.append({
                    "class": "danger",
                    "body": "Wrong Password"
                })
        else:
            msgs.append({
                "class": "danger",
                "body": "Invalid Employee ID"
            })
        return render_template("index.html", msgs=msgs)


@app.route("/password/otp", methods=["GET", "POST"])
def password_reset_form():
    msgs = []
    if request.method == "GET":
        return render_template("reset.html")
    elif request.method == "POST":
        empID = request.form.get("empID", None)
        otp_key = empID + "_ldapkey"
        if empID:
            result = ldhelper.search_user_mobile(empID)
            result2 = ldhelper.search_user_email(empID)
            if result:

                user_mobile = result[0][1]['mobile'][0]
                user_email = result2[0][1]['mail'][0]
                if redis_store.hmget(otp_key, 'otp')[0]:
                    cotp = redis_store.hmget(otp_key, 'otp')[0]
                else:
                    totp = pyotp.TOTP('base32secret')
                    cotp = totp.now()
                user_hash = hashlib.sha1(empID + user_email + cotp).hexdigest()
                # Store empID and OTP in redis, expiration time
                redis_store.hmset(otp_key, {'otp': cotp, 'key': user_hash, 'key1': user_hash, 'mail': user_email})
                redis_store.expire(otp_key, app.config.get("KEY_EXPIRATION_MINS", 10) * 60)
                timestamp = urllib.quote_plus(get_formatted_time())
		print timestamp
                endpoint = "http://www.example.com/tools/sms.php?mobile={}&transaction_id=hjfkh&variable={}:{}".format(
                    user_mobile,
                    cotp,
                    timestamp
                )
                content = urllib2.urlopen(endpoint).read()
                if content == "Sent.":
                    msgs.append({
                        "class": "success",
                        "body": "We've sent you the OTP on Registered Mobile Number"
                    })
                    flash("OTP sent Successfully to your registered mobile number")
                    return redirect(url_for("password_otp_verify", empID=empID, key=user_hash))
                else:
                    msgs.append({
                        "class": "danger",
                        "body": "There is some problem with your Registered mobile number."
                    })
            else:
                msgs.append({
                    "class": "danger",
                    "body": "Mobile Number not found with the respective Employee ID"
                })
        else:
            msgs.append({
                "class": "danger",
                "body": "Employee ID empty"
            })
        return render_template("reset.html", msgs=msgs)


@app.route("/password/otp/verify", methods=["GET", "POST"])
def password_otp_verify():
    empID = request.args.get('empID', None)
    otp_key = empID + "_ldapkey"
    user_key = request.args.get('key', None)
    if request.method == "GET":
        empID = request.args.get('empID', None)
        user_key = request.args.get('key', None)

        if empID and user_key:
            key = redis_store.hmget(otp_key, 'key1')[0]
            if key == user_key:
                verified = True
                redis_store.hdel(otp_key, 'key1')
            else:
                verified = False
        return render_template(
            "otp.html",
            verified=verified,
            empID=empID
        )
    elif request.method == "POST":
        msgs = []
        otp = request.form.get('OTP', None)
        otpredis = redis_store.hmget(otp_key, 'otp')[0]
        mailredis = redis_store.hmget(otp_key, 'mail')[0]
        if otp:
            if otp == otpredis:
                msgs.append({
                    "class": "success",
                    "body": "OTP verified Successfully and Email sent to your registered Email ID."
                })
                reset_url = "{}{}?empID={}&key={}".format(
                    app.config.get("RESET_BASE_URL", "http://localhost:5000"),
                    url_for("password_reset_verify"),
                    empID,
                    user_key
                )
                msg = Message()
		msg.subject = "Forgot Password :: Example LDAP"
                msg.sender = "ldap@example.com"
                msg.recipients = [mailredis]
                msg.body = "Goto this url to reset your password: {}".format(reset_url)
                msg.html = "Click <a href='{}'>here</a> to reset your password.\
                <br><br>You can alternatively go to this url: <br>{} <br><br> Note: The link will expire in {} hours.".format(
                    reset_url, reset_url,
                    app.config.get("KEY_EXPIRATION_HOURS", 5)
                )
                mail.send(msg)

            else:
                msgs.append({
                    "class": "danger",
                    "body": "You have Entered Wrong OTP."
                })
        else:
            msgs.append({
                "class": "danger",
                "body": "OTP Field Must Be Filled."
            })
        return render_template("reset.html", msgs=msgs)


@app.route("/password/reset/verify", methods=["GET", "POST"])
def password_reset_verify():
    if request.method == "GET":
        empID = request.args.get('empID', None)
        otp_key = empID + "_ldapkey"
        user_key = request.args.get('key', None)

        if empID and user_key:
            key = redis_store.hmget(otp_key, 'key')[0]
            if key == user_key:
                verified = True
                redis_store.delete(otp_key)
            else:
                verified = False
        return render_template(
            "password_reset.html",
            verified=verified,
            empID=empID
        )
    elif request.method == "POST":
        msgs = []
        empID = request.form.get("empID", None)
        newPwd = request.form.get(
            "newPwd", None
        )
        newPwdAgain = request.form.get(
            "newPwdAgain", None
        )
        if newPwd and newPwdAgain:
            if newPwd == newPwdAgain:
                result = ldhelper.search_user_by_uid(empID)
                cn = result[0][1]['cn'][0]
                if (ldhelper.reset_password(cn, newPwd)):
                    msgs.append({
                        "class": "success",
                        "body": "Password reset successfully"
                    })
            else:
                msgs.append({
                    "class": "danger",
                    "body": "Password do not match"
                })
        else:
            msgs.append({
                "class": "danger",
                "body": "Password and Password Again are required"
            })

        return render_template("reset.html", msgs=msgs)
