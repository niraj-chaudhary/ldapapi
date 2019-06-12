## Installation

Make sure you have `virtualenv` and `virtualenvwrapper`

```
$ sudo apt-get install python-setuptools
$ sudo easy_install pip
$ sudo pip install virtualenvwrapper
```

## App Setup

```
$ cd app_folder
$ mkvirtualenv ldap
(ldap) $ pip install -r requirements.txt
(ldap) $ export FLASK_APP=main.py
(ldap) $ export FLASK_DEBUG=1
(ldap) $ flask run
```

Now you can goto `http://localhost:5000`

> Note: To run a mail server for development run the following command
> in a terminal `python -m smtpd -n -c DebuggingServer localhost:1025`
