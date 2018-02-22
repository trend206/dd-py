from ddpy.ddan.ddan import DDAN


ddan = DDAN(api_key="", analyzer_ip="10.52.141.207")
resp = ddan.test_connection()
ddan.register()
print(resp)

resp = ddan.get_black_lists()
print(resp.__dict__)

ddan