f=open('ip_del.h','r')
ip_assigns_raw=f.readlines()
f.close()
fw=open('ip_array.h','w')
i=1
for ip_a in ip_assigns_raw:
	ip_a=ip_a.strip()
	ip_a=ip_a.split(",")
	if ip_a==[]:
		continue
	#s='["'+ip_a[0]+'",'+'"'+ip_a[1]+'",'+'"'+ip_a[2]+'"],'
	s='['+ip_a[0]+','+''+ip_a[1]+','+'"'+ip_a[2]+'"],'
	fw.write(s)
	fw.write("\n")
fw.close()
