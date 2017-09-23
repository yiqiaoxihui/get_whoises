import json


# fpw=open('/data/array_3689.json','w')
# fpr=open('/data/3689ip_json_1.txt','r')
# fpw.write('[')

# while True:
#     line = fpr.readline()
#     if line=="":
#         break
#     else:
# 		fpw.write(line)
# 		fpw.write(",")
# fpw.write(']')
# fpw.close()
# fpr.close()


fpr=open('/data/3689ip_json_1.txt','r')
#dic={}
while True:
    line = fpr.readline()
    if line=="":
        break
    else:
    	dic=json.loads(line)
    	print dic
    	