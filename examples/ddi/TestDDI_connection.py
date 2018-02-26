import ddpy.interfaces.ddi

# print list to debug console
def debugprintList(listname, list2print):
    print("")
    print(listname + " : " + str(len(list2print)))
    for i in list2print:
        print(i)

# 1. Replace the IP address below with that of your DDI appliance
ddi_ip = "192.168.44.19"

# Before calling DDI Web Service, you must add your IP (IP of the calling Python Script) to the list of
# authorized calling IP's under RDQA page under Web Services. If NAT is used,  use the NATING device IP
# in front of DDI. https://DDI-IP/html/rdqa.htm


# Create a Client instance
c = ddpy.interfaces.ddi.DDI(ddi_ip, disable_cert_checking=True)

# Make sure you have entries in Deny and Allow list so you can test.
# Get IP White List aka Allow List in UI.  Response is a list.
ip_whitelists = c.get_ip_whitelists()
# printing the list to the console...
debugprintList("White List IP", ip_whitelists)

#you can do the same for url, domain and sha1
debugprintList("White List File SHA1", c.get_sha1_whitelists())
debugprintList("White List URL's", c.get_url_whitelists())
debugprintList("White List Domains", c.get_domain_whitelists())
#Test DDI Deny List
debugprintList("Black List IP", c.get_ip_blacklists())
debugprintList("Black List Domains", c.get_domain_blacklists())
debugprintList("Black List File SHA1", c.get_sha1_blacklists())
debugprintList("Black List URL's", c.get_url_blacklists())










