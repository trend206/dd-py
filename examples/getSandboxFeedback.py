from ddpy.interfaces.ddi import DDI

# 1. Replace the IP address below with that of your DDI appliance
ddi_ip = "192.168.44.19"

# Create a Client instance
c = DDI(ddi_ip, disable_cert_checking=True)

print("")
print("get_cnc_callback_addresses")
print(c.get_cnc_callback_addresses())

print("")
print("get_BlackLists")
print(c.get_blacklists())

print("")
print("get_sandbox_feedback_blacklists")
print(c.get_sandbox_feedback_blacklists())

print("")
print("get_whitelists")
print(c.get_whitelists())