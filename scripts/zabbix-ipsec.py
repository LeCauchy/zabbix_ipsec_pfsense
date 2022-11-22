#!/usr/local/bin/python3.8

import re
import sys
import xml.etree.cElementTree as ET

IPSEC_CONF = './swanctl.conf'
rtt_time_warn = 200
rtt_time_error = 300


#Function to set correct format on ikeId. Recives conIDXXX, return ID
def formatIkeId(ikeid):
    
    #Convert list  into a string
    ikeid = ikeid[0]

    #If ikeid has 8 or more positions, get the position 3 and 4
    if len(ikeid) >= 8:
        ikeid = ikeid[3] + ikeid[4]
    else:
        #Else, get only the position 3. That is because some ikeids are small
        ikeid = ikeid[3]
    #print "The correct ike id is ", ikeid
    return ikeid

def parseConf():
    reg_conn = re.compile('^\s*con[0-9]*')
    reg_left = re.compile('local_addrs = .*')
    reg_right = re.compile('remote_addrs = .*')
    reg_descr = re.compile('\t\t.*ikeid.*')
    # reg_rightsubnet = re.compile('.*remote_ts =(.*).*')
    data = {}
    with open(IPSEC_CONF, 'r') as f:
        soubor = f.read()
        groups = re.findall('(^\s*con[0-9]+ \{.*?)(?=^\s*esp_proposals|\Z)', soubor, flags=re.DOTALL|re.MULTILINE)
        for g in groups:
            conn_tmp = list()
            m = re.search(reg_conn, g)
            m = m.group()
            m = m.lstrip('\t')
            m = m.replace('\n\t','')
            if m:
                conn_tmp.append(m)
            left_tmp = list()
            m1 = re.search(reg_left, g)
            m1 = m1.group()
            m1 = m1.strip('\t\tlocal_addrs =')
            if m1:
                left_tmp.append(m1)
            right_tmp = list()
            m2 = re.search(reg_right, g)
            m2 = m2.group()
            m2 = m2.strip('\t\tremote_addrs =')
            if m2:
                right_tmp.append(m2)
            descr = "Not found"
            descr_tmp = list()
            m3 = re.search(reg_descr, g)
            m3 = m3.group()
            m3 = m3.strip('\t\t# .*:')
            if m3:
                descr_tmp.append(m3)
            if conn_tmp and left_tmp and right_tmp and descr_tmp:
                    data[conn_tmp[0]] = [left_tmp[0], right_tmp[0], descr_tmp[0]]

        return data

def getTemplate():
    template = """
        {{ "{{#TUNNEL}}":"{0}","{{#TARGETIP}}":"{1}","{{#SOURCEIP}}":"{2}","{{#DESCRIPTION}}":"{3}" }}"""

    return template

def getPayload():
    final_conf = """{{
    "data":[{0}
    ]
}}"""

    conf = ''
    data = parseConf().items()
    for key,value in data:
        tmp_conf = getTemplate().format(
            key,
            value[1],
            value[0],
            value[2],
            rtt_time_warn,
            rtt_time_error
        )
        if len(data) > 1:
            conf += '%s,' % (tmp_conf)
        else:
            conf = tmp_conf
    if conf[-1] == ',':
        conf=conf[:-1]
    return final_conf.format(conf)

if __name__ == "__main__":
    ret = getPayload()
    sys.exit(ret)