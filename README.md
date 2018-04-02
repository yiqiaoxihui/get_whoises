# get_whoises
a python program to localize whois date from five RIRs.


Three parts of whois

1.whois mirror
include complete ripe and afrinic data 
path:/Download/whois-whois-1.87
run:./whois.init start
attention:set jdk 
export JAVA_HOME=/home/Document/jdk1.8.0_151
export PATH=$JAVA_HOME/bin:$PATH
export CLASSPATH=.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar

2.complete inetnums of arin and apnic
path: /home/hitnis/Download/auto_download_raw_whois/auto_download_inetnum_and_insert_db.py
store mongodb:arin,apnic

3.lacnic and other rir.eg.whois.nic.or.kr
path:/home/hitnis/Document/get_whoises/prefect_only_lacnic_V_0_1.py
store mongodb:lacnic
