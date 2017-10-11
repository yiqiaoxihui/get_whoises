import re
import os
import socket
import struct
import hashlib
from pymongo import MongoClient

conn=MongoClient('127.0.0.1',27017)
db=conn.ly
my_mongo=db.whois

hash_dic={}
rows=my_mongo.find({},{'hash':1})
for row in rows:
	hash_dic[row['hash']]=1
def md5(str):
    import hashlib
    m = hashlib.md5()  
    m.update(str)
    return m.hexdigest()
print len(md5('df'))
# content='NetRange: 140.224.0.0 - 140.224.255.255\nCIDR: 140.224.0.0/16\nNetName: APNIC-ERX-140-224-0-0\nNetHandle: NET-140-224-0-0-1\nParent: NET140 (NET-140-0-0-0-0)\nNetType: Early Registrations, Transferred to APNIC\nOriginAS: \nOrganization: Asia Pacific Network Information Centre (APNIC)\nRegDate: 2010-11-03\nUpdated: 2010-11-17\nComment: This IP address range is not registered in the ARIN database.\nComment: This range was transferred to the APNIC Whois Database as\nComment: part of the ERX (Early Registration Transfer) project.\nComment: For details, refer to the APNIC Whois Database via\nComment: WHOIS.APNIC.NET or http://wq.apnic.net/apnic-bin/whois.pl\nComment: \nComment: ** IMPORTANT NOTE: APNIC is the Regional Internet Registry\nComment: for the Asia Pacific region. APNIC does not operate networks\nComment: using this IP address range and is not able to investigate\nComment: spam or abuse reports relating to these addresses. For more\nComment: help, refer to http://www.apnic.net/apnic-info/whois_search2/abuse-and-spamming\nRef: https://whois.arin.net/rest/net/NET-140-224-0-0-1\n\nResourceLink: http://wq.apnic.net/whois-search/static/search.html\nResourceLink: whois.apnic.net\n\nOrgName: Asia Pacific Network Information Centre\nOrgId: APNIC\nAddress: PO Box 3646\nCity: South Brisbane\nStateProv: QLD\nPostalCode: 4101\nCountry: AU\nRegDate: \nUpdated: 2012-01-24\nRef: https://whois.arin.net/rest/org/APNIC\n\nReferralServer: whois://whois.apnic.net\nResourceLink: http://wq.apnic.net/whois-search/static/search.html\n\nOrgTechHandle: AWC12-ARIN\nOrgTechName: APNIC Whois Contact\nOrgTechPhone: +61 7 3858 3188 \nOrgTechEmail: search-apnic-not-arin@apnic.net\nOrgTechRef: https://whois.arin.net/rest/poc/AWC12-ARIN\n\nOrgAbuseHandle: AWC12-ARIN\nOrgAbuseName: APNIC Whois Contact\nOrgAbusePhone: +61 7 3858 3188 \nOrgAbuseEmail: search-apnic-not-arin@apnic.net\nOrgAbuseRef: https://whois.arin.net/rest/poc/AWC12-ARIN\n\nFound a referral to whois.apnic.net.\n\ninetnum: 140.224.0.0 - 140.224.127.255\nnetname: CHINANET-FJ\ndescr: CHINANET FUJIAN NETWORK\ncountry: CN\nadmin-c: CA67-AP\ntech-c: CA67-AP\nstatus: ALLOCATED NON-PORTABLE\nmnt-by: MAINT-CHINANET-FJ\nmnt-lower: MAINT-CHINANET-FJ\nmnt-routes: MAINT-CHINANET-FJ\nmnt-irt: IRT-CHINANET-FJ\nchanged: zhengzm@gsta.com 20130128\nsource: APNIC\n\nirt: IRT-CHINANET-FJ\naddress: no.7,dongjie road,fuzhou,fujian,china\ne-mail: fjnic@fjdcb.fz.fj.cn\nabuse-mailbox: abuse@fjdcb.fz.fj.cn\nadmin-c: CA67-AP\ntech-c: CA67-AP\nauth: # Filtered\nmnt-by: MAINT-CHINANET-FJ\nchanged: fjnic@fjdcb.fz.fj.cn 20101206\nsource: APNIC\n\nrole: CHINANETFJ IP ADMIN\naddress: 7,East Street,Fuzhou,Fujian,PRC\ncountry: CN\nphone: +86-591-83309761\nfax-no: +86-591-83371954\ne-mail: fjnic@fjdcb.fz.fj.cn\nremarks: send spam reports and abuse reports\nremarks: to abuse@fjdcb.fz.fj.cn\nremarks: Please include detailed information and\nremarks: times in UTC\nadmin-c: FH71-AP\ntech-c: FH71-AP\nnic-hdl: CA67-AP\nremarks: www.fjtelecom.com\nnotify: fjnic@fjdcb.fz.fj.cn\nmnt-by: MAINT-CHINANET-FJ\nchanged: fjnic@fjdcb.fz.fj.cn 20100108\nsource: APNIC\nchanged: hm-changed@apnic.net 20111114'
# position=content.find('Found a referral to')
# position=content.find('inetnum',position)
# content=content[position:]
# ip_range=re.findall(r"{0,}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", content)
# print ip_range