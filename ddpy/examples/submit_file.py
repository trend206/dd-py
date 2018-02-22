from ddpy.ddan.ddan import DDAN


ddan = DDAN(api_key="", analyzer_ip="")
resp = ddan.submit_file('/Users/jeff/Downloads/word_sample_20180222145346.doc')
print(resp)

