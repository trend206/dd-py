from ddpy.interfaces.ddan import DDAN


ddan = DDAN(api_key="", analyzer_ip="")

resp = ddan.test_connection()

print(resp)


