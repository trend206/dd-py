# Class to help access Trend Micro Deep Discovery Inspector
# See the license at module level
import ssl, socket, json, re
from suds.client import Client as SudsClient #suds-py3
from suds.transport.https import HttpAuthenticated
from urllib.request import HTTPSHandler


class CustomTransport(HttpAuthenticated):
    def u2handlers(self):
        # use handlers from superclass
        handlers = HttpAuthenticated.u2handlers(self)
        # create custom ssl context, e.g.:
        ctx = ssl._create_unverified_context()
        # configure context as needed...
        ctx.check_hostname = False
        # add a https handler using the custom context
        handlers.append(HTTPSHandler(context=ctx))
        return handlers


class DDI():
    '''A client object for interacting with DDI's SOAP API.'''

    def __init__(self, ddi_ip, disable_cert_checking=True):
        '''Initialize the client connection to the DDI's API.'''
        if not ((type(ddi_ip) == str) or (self.is_valid_hostname(ddi_ip))):
            raise ValueError(
                "Client __init__ parameter 'ddi_ip' must be a STRING that contains a valid IP address or hostname.")
        if not (type(disable_cert_checking) == bool):
            raise ValueError(
                "Client __init__ parameter 'disable_cert_checking' must be a BOOL that is either True or False")
        self.ddi_ip = ddi_ip
        self.wsdl_url = 'https://{0}/api/?WSDL'.format(self.ddi_ip)
        if disable_cert_checking == True:
            c = SudsClient(self.wsdl_url, cache=None,
                           transport=CustomTransport())  # To disable warning for Self-Signed Certificates
        else:
            c = SudsClient(self.wsdl_url)
        self.client = c

    def is_valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def is_valid_hostname(self, hostname):
        # TODO: Make a better regex
        if re.match(
                "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$",
                hostname):
            return True
        else:
            return False

    def get_ip_blacklists(self):
        '''Get the IP Blacklist (aka: The 'Deny List').  Returns the IP blacklist as a list'''
        ip_blacklist = self.client.service.get_ip_blacklists()
        ip_list = []
        if ip_blacklist:
            for ip in ip_blacklist[0]:
                ip_list.append(ip["iprange"])
        return ip_list

    def get_sha1_blacklists(self):
        '''Get the SHA1 Blacklist (aka: The 'Deny List').  Returns the SHA1 blacklist as a list'''
        sha1_blacklist = self.client.service.get_sha1_blacklists()
        sha1_list = []
        if sha1_blacklist:
            for sha1 in sha1_blacklist[0]:
                sha1_list.append(sha1["sha1"])
        return sha1_list

    def get_url_blacklists(self):
        '''Get the URL Blacklist (aka: The 'Deny List').  Returns the url blacklist as a list'''
        url_blacklist = self.client.service.get_url_blacklists()
        url_list = []
        if len(url_blacklist) > 0:
            for url in url_blacklist[0]:
                url_list.append(url["url"])
        return url_list

    def get_domain_blacklists(self):
        '''Get the Domain Blacklist (aka: The 'Deny List').  Returns the domain blacklist as a list'''
        domain_blacklist = self.client.service.get_domain_blacklists()
        domain_list = []
        if len(domain_blacklist) > 0:
            for domain in domain_blacklist[0]:
                domain_list.append(domain["domain"])
        return domain_list

    def get_blacklists(self):
        '''Get the entire Blacklist (aka: The 'Deny List').  Returns the entire blacklist as a list'''
        blacklists = self.client.service.get_blacklists()
        domain_blacklist = []
        if blacklists["domain_blacklists"]:
            for domain in blacklists["domain_blacklists"][0]:
                domain_blacklist.append(domain["domain"])
        ip_blacklist = []
        if blacklists["ip_blacklists"]:
            for ip in blacklists["ip_blacklists"][0]:
                ip_blacklist.append(ip["iprange"])
        url_blacklist = []
        if blacklists["url_blacklists"]:
            for url in blacklists["url_blacklists"][0]:
                url_blacklist.append(url["url"])
        sha1_blacklist = []
        if blacklists["sha1_blacklists"]:
            for sha1 in blacklists["sha1_blacklists"][0]:
                sha1_blacklist.append(sha1["sha1"])
        return json.dumps({"domain_blacklist": domain_blacklist,
                           "ip_blacklist": ip_blacklist,
                           "url_blacklist": url_blacklist,
                           "sha1_blacklist": sha1_blacklist})

    def reset_ip_blacklists(self):
        '''Clears the IP Blacklist'''
        self.client.service.reset_ip_blacklists()

    def reset_sha1_blacklists(self):
        '''Clears the SHA1 Blacklist'''
        self.client.service.reset_sha1_blacklists()

    def reset_url_blacklists(self):
        '''Clears the URL Blacklist'''
        self.client.service.reset_url_blacklists()

    def reset_domain_blacklists(self):
        '''Clears the Domain Blacklist'''
        self.client.service.reset_domain_blacklists()

    def reset_blacklists(self):
        '''Clears all Blacklists (aka: Deny List)'''
        self.client.service.reset_blacklists()

    def set_ip_blacklists(self, ip_list, comment='Added via WebAPI'):
        '''Sets the IP blacklist (aka: IP Deny List).  Note:  This method OVERWRITES any existing IP Blacklist items.'''
        # Note:  Maybe create another def to add IPs to the blacklist.
        action_enum = self.client.factory.create('ActionEnumeration')
        source_type_enum = self.client.factory.create('SourceTypeEnumeration')
        ip_blacklists = {
            'IPBlacklist': []
        }
        for ip in ip_list:
            ip_blacklists['IPBlacklist'].append({'iprange': ip,
                                                 'source_type': source_type_enum.UserAdded,
                                                 'action': action_enum.Monitor,
                                                 'comments': comment,
                                                 })
        self.client.service.set_ip_blacklists(ip_blacklists)

    def set_sha1_blacklists(self, sha1_list):
        '''Sets the sha1 blacklist (aka: sha1 Deny List).  Note:  This method OVERWRITES any existing sha1 Blacklist items.'''
        # Note:  Maybe create another def to add sha1s to the blacklist.
        action_enum = self.client.factory.create('ActionEnumeration')
        source_type_enum = self.client.factory.create('SourceTypeEnumeration')
        sha1_blacklists = {
            'SHA1Blacklist': []
        }
        for sha1 in sha1_list:
            sha1_blacklists['SHA1Blacklist'].append({'sha1': sha1,
                                                     'source_type': source_type_enum.UserAdded,
                                                     'action': action_enum.Monitor,
                                                     'comments': 'Added via WebAPI',
                                                     })
        self.client.service.set_sha1_blacklists(sha1_blacklists)

    def set_url_blacklists(self, url_list):
        '''Sets the url blacklist (aka: url Deny List).  Note:  This method OVERWRITES any existing url Blacklist items.'''
        # Note:  Maybe create another def to add urls to the blacklist.
        action_enum = self.client.factory.create('ActionEnumeration')
        source_type_enum = self.client.factory.create('SourceTypeEnumeration')
        url_blacklists = {
            'URLBlacklist': []
        }
        for url in url_list:
            url_blacklists['URLBlacklist'].append({'url': url,
                                                   'source_type': source_type_enum.UserAdded,
                                                   'action': action_enum.Monitor,
                                                   'comments': 'Added via WebAPI',
                                                   })
        self.client.service.set_url_blacklists(url_blacklists)

    def set_domain_blacklists(self, domain_list):
        '''Sets the domain blacklist (aka: domain Deny List).  Note:  This method OVERWRITES any existing domain Blacklist items.'''
        # Note:  Maybe create another def to add domains to the blacklist.
        action_enum = self.client.factory.create('ActionEnumeration')
        source_type_enum = self.client.factory.create('SourceTypeEnumeration')
        domain_blacklists = {
            'DomainBlacklist': []
        }
        for domain in domain_list:
            domain_blacklists['DomainBlacklist'].append({'domain': domain,
                                                         'source_type': source_type_enum.UserAdded,
                                                         'action': action_enum.Monitor,
                                                         'comments': 'Added via WebAPI',
                                                         })
        self.client.service.set_domain_blacklists(domain_blacklists)

        # def set_blacklists(self, blacklist_dictionary):   # FINISH LATER
        '''Sets ALL blacklists (IP, SHA1, URL, Domain)'''

    def get_ip_whitelists(self):
        '''Get the IP Whitelist (aka: The IP 'Allow List').  Returns the IP Whitelist as a list'''
        ip_whitelist = self.client.service.get_ip_whitelists()
        ip_list = []
        if ip_whitelist:
            for ip in ip_whitelist[0]:
                ip_list.append(ip["iprange"])
        return ip_list

    def get_sha1_whitelists(self):
        '''Get the SHA1 whitelist (aka: The 'Deny List').  Returns the SHA1 whitelist as a list'''
        sha1_whitelist = self.client.service.get_sha1_whitelists()
        sha1_list = []
        if sha1_whitelist:
            for sha1 in sha1_whitelist[0]:
                sha1_list.append(sha1["sha1"])
        return sha1_list

    def get_url_whitelists(self):
        '''Get the url whitelist (aka: The 'Deny List').  Returns the url whitelist as a list'''
        url_whitelist = self.client.service.get_url_whitelists()
        url_list = []
        if len(url_whitelist) > 0:
            for url in url_whitelist[0]:
                url_list.append(url["url"])
        return url_list

    def get_domain_whitelists(self):
        '''Get the domain whitelist (aka: The 'Deny List').  Returns the domain whitelist as a list'''
        domain_whitelist = self.client.service.get_domain_whitelists()
        domain_list = []
        if len(domain_whitelist) > 0:
            for domain in domain_whitelist[0]:
                domain_list.append(domain["domain"])
        return domain_list

    def get_whitelists(self):
        '''Get the entire whitelist (aka: The 'Allow List').  Returns the entire whitelist as a list'''
        whitelists = self.client.service.get_whitelists()
        all_list = []
        if len(whitelists) > 0:
            for item in whitelists:
                all_list.append(list(item))
        return whitelists #all_list

    def reset_ip_whitelists(self):
        '''Clears the IP whitelist'''
        self.client.service.reset_ip_whitelists()

    def reset_sha1_whitelists(self):
        '''Clears the SHA1 whitelist'''
        self.client.service.reset_sha1_whitelists()

    def reset_url_whitelists(self):
        '''Clears the URL whitelist'''
        self.client.service.reset_url_whitelists()

    def reset_domain_whitelists(self):
        '''Clears the Domain whitelist'''
        self.client.service.reset_domain_whitelists()

    def reset_whitelists(self):
        '''Clears all whitelists (aka: Deny List)'''
        self.client.service.reset_whitelists()

    def set_ip_whitelists(self, ip_list):
        '''Sets the IP whitelist (aka: IP Deny List).  Note:  This method OVERWRITES any existing IP whitelist items.'''
        # Note:  Maybe create another def to add IPs to the whitelist.
        source_type_enum = self.client.factory.create('SourceTypeEnumeration')
        ip_whitelists = {
            'IPWhitelist': []
        }
        for ip in ip_list:
            ip_whitelists['IPWhitelist'].append({'iprange': ip,
                                                 'source_type': source_type_enum.UserAdded,
                                                 'comments': 'Added via WebAPI',
                                                 })
        self.client.service.set_ip_whitelists(ip_whitelists)

    def set_sha1_whitelists(self, sha1_list):
        '''Sets the sha1 whitelist (aka: sha1 Deny List).  Note:  This method OVERWRITES any existing sha1 whitelist items.'''
        # Note:  Maybe create another def to add sha1s to the whitelist.
        source_type_enum = self.client.factory.create('SourceTypeEnumeration')
        sha1_whitelists = {
            'SHA1Whitelist': []
        }
        for sha1 in sha1_list:
            sha1_whitelists['SHA1Whitelist'].append({'sha1': sha1,
                                                     'source_type': source_type_enum.UserAdded,
                                                     'comments': 'Added via WebAPI',
                                                     })
        self.client.service.set_sha1_whitelists(sha1_whitelists)

    def set_url_whitelists(self, url_list):
        '''Sets the url whitelist (aka: url Deny List).  Note:  This method OVERWRITES any existing url whitelist items.'''
        # Note:  Maybe create another def to add urls to the whitelist.
        source_type_enum = self.client.factory.create('SourceTypeEnumeration')
        url_whitelists = {
            'URLWhitelist': []
        }
        for url in url_list:
            url_whitelists['URLWhitelist'].append({'url': url,
                                                   'source_type': source_type_enum.UserAdded,
                                                   'comments': 'Added via WebAPI',
                                                   })
        self.client.service.set_url_whitelists(url_whitelists)

    def set_domain_whitelists(self, domain_list):
        '''Sets the domain whitelist (aka: domain Allow List).  Note:  This method OVERWRITES any existing domain whitelist items.'''
        # Note:  Maybe create another def to add domains to the whitelist.
        source_type_enum = self.client.factory.create('SourceTypeEnumeration')
        domain_whitelists = {
            'DomainWhitelist': []
        }
        for domain in domain_list:
            domain_whitelists['DomainWhitelist'].append({'domain': domain,
                                                         'source_type': source_type_enum.UserAdded,
                                                         'comments': 'Added via WebAPI',
                                                         })
        self.client.service.set_domain_whitelists(domain_whitelists)

        # def set_whitelists(self, whitelist_dictionary):   # FINISH LATER
        '''Sets ALL whitelists (IP, SHA1, URL, Domain)'''

    def get_sandbox_feedback_blacklists(self):
        '''Gets the Suspicious Objects list from Virtual Analysis (aka: the sandbox).  Returns list in JSON format'''
        SO_feedback = self.client.service.get_sandbox_feedback_blacklists()
        domain_blacklist = []
        if SO_feedback["domain_blacklists"]:
            for domain in SO_feedback["domain_blacklists"][0]:
                domain_blacklist.append(domain["domain"])
        ip_blacklist = []
        if SO_feedback["ip_blacklists"]:
            for ip in SO_feedback["ip_blacklists"][0]:
                ip_blacklist.append(ip["iprange"])
        url_blacklist = []
        if SO_feedback["url_blacklists"]:
            for url in SO_feedback["url_blacklists"][0]:
                url_blacklist.append(url["url"])
        sha1_blacklist = []
        if SO_feedback["sha1_blacklists"]:
            for sha1 in SO_feedback["sha1_blacklists"][0]:
                sha1_blacklist.append(sha1["sha1"])
        return json.dumps({"domain_blacklist": domain_blacklist,
                           "ip_blacklist": ip_blacklist,
                           "url_blacklist": url_blacklist,
                           "sha1_blacklist": sha1_blacklist})

    def get_cnc_callback_addresses(self):
        '''Gets the CNC Callback Addresses discovered by DDI'''
        # MODIFY THIS TO RETURN IN JSON FORMAT
        # Need to get some TEST DATA!!!
        cnc_addresses = self.client.service.get_cnc_callback_addresses()
        return cnc_addresses

    def get_openioc(self, sha1):
        '''Gets the OpenIOC string for a given SHA1'''
        openioc = self.client.service.get_openioc(sha1)
        return openioc["openioc"]