import ldap
import sys


class LDAPHelper():

    def __init__(self, app=None):
        self.app = app
        self.conn = self.connection()

    def connect(self, ldap_uri):
        return ldap.initialize(ldap_uri)

    def get_dc(self):
        return self.app.config.get("LDAP_DC", "dc=example,dc=com")

    def get_cn(self):
        return self.app.config.get("LDAP_CN", "cn=Manager")

    def get_default_password(self):
        return self.app.config.get("LDAP_DEFAULT_PWD", "example@321")

    def search_user_by_uid(self, uid):
        basedn = "ou=People," + self.get_dc()
        search_filter = "(uid={})".format(uid)
        search_attr = ["cn"]
        return self.conn.search_s(
            basedn, ldap.SCOPE_SUBTREE,
            search_filter, search_attr
        )

    def search_user_email(self, uid):
        basedn = "ou=People," + self.get_dc()
        search_filter = "(uid={})".format(uid)
        search_attr = ["mail"]
        return self.conn.search_s(
            basedn, ldap.SCOPE_SUBTREE,
            search_filter, search_attr
        )

    def search_user_mobile(self, uid):
        basedn = "ou=People," + self.get_dc()
        search_filter = "(uid={})".format(uid)
        search_attr = ["mobile"]
        return self.conn.search_s(
            basedn, ldap.SCOPE_SUBTREE,
            search_filter, search_attr
        )

    def verify_password(self, cn, pwd):
        con = ldap.initialize("ldap://localhost")
        dnq = "cn={},ou=People," + self.get_dc()
        dnq = dnq.format(cn)
        try:
            con.simple_bind_s(dnq, pwd)
        except ldap.INVALID_CREDENTIALS:
            con.unbind()
            del con
            return False
        con.unbind()
        del con
        return True

    def change_password(self, cn, newPwd):
        dnq = "cn={},ou=People," + self.get_dc()
        dnq = dnq.format(cn)
        mod_attrs = [
            (ldap.MOD_REPLACE, "userPassword", str(newPwd))
        ]
        try:
            self.conn.modify_s(dnq, mod_attrs)
        except Exception, e:
            if type(e.message) == dict and 'desc' in e.message.keys():
                self.app.logger.debug(e.message['desc'])
                return False
            else:
                self.app.logger.debug(e)
                return False
        return True

    def reset_password(self, cn, newPwd):
        return self.change_password(cn, newPwd)

    def connection(self):
        # Fetch configs
        ldap_uri = self.app.config.get("LDAP_CONNECT_URI", "ldap://localhost")
        cn = self.get_cn() + ","
        dc = self.get_dc()
        pwd = self.app.config.get("LDAP_PWD", "")

        self.app.logger.debug("Connecting to LDAP: {}".format(ldap_uri))
        # Connect and bind to ldap
        try:
            ldap_con = self.connect(self.app.config.get("LDAP_CONNECT_URI"))
            self.app.logger.debug("Binding: {}".format(cn + dc))
            ldap_con.simple_bind_s(cn + dc, pwd)
        except Exception, e:
            if type(e.message) == dict and 'desc' in e.message.keys():
                print e.message['desc']
                self.app.logger.debug(e.message['desc'])
            else:
                self.app.logger.debug(e)
            self.app.logger.error(
                "Failed to connect to ldap server. \
Please make sure you have correct configs."
            )
        return ldap_con
