import json
'''
load json file test


'''
with open('/home/ly/1.json') as json_file:
	data=json.load(json_file)
	for item in data:
		if item["IP_addr"]=="200.131.10.245":
			print item['whois']['owner']
	# with open('/home/ly/8724.json','w') as json_file1:
	# 	json_file1.write(data)
