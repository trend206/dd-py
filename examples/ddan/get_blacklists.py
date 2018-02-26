from ddpy.interfaces.ddan import DDAN


ddan = DDAN(api_key="", analyzer_ip="")
resp = ddan.get_black_lists()

print(resp.content)

