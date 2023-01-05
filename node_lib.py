import base64
import lib
import urllib.parse
import re
import json


def check_ss(ss_list, ss_uri):
    """检测ss节点是否与列表重复"""
    if ss_uri[:5] != 'ss://':
        return False
    if not ss_list:
        return 0
    ss_dict0 = ss_decode(ss_uri)
    # print(ss_dict0)
    for i in ss_list:
        if i[:5] != 'ss://':
            continue
        else:
            ss_dict1 = ss_decode(i)
            if ss_dict0['cipher'] == ss_dict1['cipher'] \
                    and ss_dict0['password'] == ss_dict1['password'] \
                    and ss_dict0['server'] == ss_dict1['server'] \
                    and ss_dict0['port'] == ss_dict1['port']:
                return 1
    return 0


def check_trojan(trojan_list, trojan_uri):
    """检测trojan节点是否与列表重复"""
    if trojan_uri[:9] != 'trojan://':
        return False
    code2 = re.match(r'trojan://(.*)#(.*)', trojan_uri)
    for i in trojan_list:
        if i[:9] != 'trojan://':
            continue
        else:
            code1 = re.match(r'trojan://(.*)#(.*)', i)
            if code1.group(1) == code2.group(1):
                return 1
    return 0


def check_vmess_dict(vmess_dict):
    """检测vmess节点格式是否符合规范"""
    code_list = ["add", "port", "id", "aid", "net", "host", "path", "tls"]
    for i in code_list:
        if i not in vmess_dict.keys():
            return False
    return True


def check_vmess(vmess_list, vmess_uri):
    """检测vmess节点是否与列表重复"""
    if vmess_uri[:8] != 'vmess://':
        return False
    if not vmess_list:
        return 0
    vmess_dict0 = vmess_decode(vmess_uri)
    if not check_vmess_dict(vmess_dict0):
        raise
    else:
        for i in vmess_list:
            if i[:8] != 'vmess://':
                continue
            else:
                vmess_dict1 = vmess_decode(i)
                if vmess_dict1['add'] == vmess_dict0['add'] and vmess_dict1['port'] == vmess_dict0['port'] and \
                        vmess_dict1['id'] == vmess_dict0['id']:
                    return 1
        return 0


def decode_base64(str_code):
    """base64解码函数"""
    missing_padding = len(str_code) % 4
    if missing_padding:
        str_code += '=' * (4 - missing_padding)
    a = base64.b64decode(bytes(str_code.strip(), encoding="utf-8"))
    return str(a, encoding='utf-8')


def ss_decode(ss_uri):
    """
    ss节点链接base64解码函数
    编码格式 ss://[cipher]:[password]@[server]:[port]
    """
    try:
        code = re.match(r'ss://(.*)#(.*)', ss_uri)
        name = urllib.parse.unquote(code.group(2))

        if lib.is_base64(code.group(1)) == 1:
            content = decode_base64(code.group(1))
            # print('content=', content)
            content = re.match(r'(.*?):(.*)@(.*):([0-9]{1,5})', content)
            content = {
                'name': name,
                'type': 'ss',
                'cipher': content.group(1),
                'password': content.group(2),
                'server': content.group(3),
                'port': content.group(4)
            }
            return content
        else:
            code1 = re.match(r'(.*)@(.*):([0-9]*)', code.group(1))
            code2 = re.match(r'(.*?):(.*)', decode_base64(code1.group(1)))
            content = {
                'name': name,
                'type': 'ss',
                'cipher': code2.group(1),
                'password': code2.group(2),
                'server': code1.group(2),
                'port': code1.group(3)
            }
            return content
    except Exception as error:
        print(error)
        print(ss_uri)


def ss_encode(ss_dict):
    """
    ss节点base64编码函数
    编码格式 ss://[cipher]:[password]@[server]:[port]
    """
    if type(ss_dict['port']) != str:
        ss_dict['port'] = str(ss_dict['port'])
    else:
        pass
    code = 'ss://' + str(base64.b64encode(
        bytes(ss_dict['cipher'] + ':' + str(ss_dict['password']) + '@' + ss_dict['server'] + ':' + ss_dict['port'],
              encoding='utf-8')), encoding='utf-8')
    if 'name' in ss_dict.keys():
        remarks = urllib.parse.quote(ss_dict['name'])
        code = code + '#' + remarks
    return code


def trojan_decode(trojan_uri):
    """
    trojan节点base64解码函数
    编码格式 trojan://[password]@[server]:[port]?sni=[sni]
    """
    print(trojan_uri)
    code = re.match(r'trojan://(.*)#(.*)', trojan_uri)
    content = code.group(1).split('?')
    content1 = re.match(r'(.*)@(.*):([0-9]{1,5})', content[0])
    parameter = {}
    if len(content) >= 2:
        print(content[1])
        for i in content[1].split('&'):
            parameter[i.split('=')[0]] = i.split('=')[1]
    name = urllib.parse.unquote(code.group(2))
    parameter['name'] = name
    parameter['type'] = 'trojan'
    parameter['password'] = content1.group(1)
    parameter['server'] = content1.group(2)
    parameter['port'] = content1.group(3)
    return parameter


def trojan_encode(trojan_dict):
    """
    trojan节点base64编码函数
    编码格式 trojan://[password]@[server]:[port]?sni=[sni]
    """
    if type(trojan_dict['port']) != str:
        trojan_dict['port'] = str(trojan_dict['port'])
    code = 'trojan://' + str(trojan_dict['password']) + '@' + trojan_dict['server'] + ':' + trojan_dict['port'] + '?'
    for i in trojan_dict:
        if i not in ['password', 'server', 'port', 'name', 'type']:
            code = code + i + "=" + str(trojan_dict[i]) + '&'
    code = code[:-1]
    if 'name' in trojan_dict.keys():
        remarks = urllib.parse.quote(trojan_dict['name'])
        code = code + '#' + remarks
    return code


def vmess_decode(vmess_uri):
    """
    vmess节点base64解码函数
    编码格式 {"v": "2","ps": "美国123456","add": "47.242.38.105","port": "443","id": "fd4668b8-45d3-32f1-b5b8-195aa0d407c3","aid": "1","net": "ws","type": "none","host": "s253.snode.xyz","path": "/panel","tls": "tls"}
    """
    code = re.match(r'vmess://(.*)', vmess_uri)
    data1 = decode_base64(code.group(1))
    try:
        dict1 = json.loads(data1)
        dict1['type'] = 'vmess'
        return dict1
    except ValueError:
        try:
            dict1 = eval(data1)
            dict1['type'] = 'vmess'
            return dict1
        except Exception as error:
            print(error)


def vmess_encode(vmess_dict, flag=''):
    """
    vmess节点base64编码函数,flag = 'base64'输出uri，其他输出字典
    编码格式 {"v": "2","ps": "美国123456","add": "47.242.38.105","port": "443","id": "fd4668b8-45d3-32f1-b5b8-195aa0d407c3","aid": "1","net": "ws","type": "none","host": "s253.snode.xyz","path": "/panel","tls": "tls"}
    输入格式 {name:152,server: 154.84.1.235,port: 443,type: vmess,uuid: d15111f5-ad92-4175-a238-7266cf665786,alterId: 64,cipher: auto,tls: true,network: ws,ws-path: /footers,ws-headers: {Host: www.9142674173.xyz}}
    """

    if not check_vmess_dict(vmess_dict):
        code_dict = {
            "v": "2",
            "ps": "",
            "add": vmess_dict['server'],
            "port": vmess_dict["port"],
            "id": vmess_dict["uuid"],
            "aid": vmess_dict["alterId"],
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "",
            "path": "",
            "tls": ""
        }
        if 'network' in vmess_dict.keys():
            code_dict["net"] = vmess_dict["network"]
        if 'name' in vmess_dict.keys():
            code_dict["ps"] = vmess_dict['name']
        if vmess_dict["tls"] is True or vmess_dict["tls"] == "tls":
            code_dict["tls"] = "tls"
        if 'ws-headers' in vmess_dict.keys():
            if "Host" in vmess_dict["ws-headers"].keys():
                code_dict["host"] = vmess_dict["ws-headers"]["Host"]
        if 'ws-path' in vmess_dict.keys():
            code_dict["path"] = vmess_dict['ws-path']
        if flag == 'base64':
            code = 'vmess://' + encode_base64(code_dict)
            return code
        else:
            return code_dict
    else:
        if flag == 'base64':
            code = 'vmess://' + encode_base64(vmess_dict)
            return code
        else:
            return vmess_dict


def encode_base64(my_str):
    """base64编码"""
    return str(base64.b64encode(bytes(str(my_str), encoding='utf-8')), encoding='utf-8')


def node_decoder(uri):
    if re.match(r'vmess://(.*)', uri):
        dict1 = vmess_decode(uri)
    elif re.match(r'trojan://(.*)', uri):
        dict1 = trojan_decode(uri)
    elif re.match(r'ss://(.*)', uri):
        dict1 = ss_decode(uri)
    else:
        return False
    return dict1


def subscribe_to_list(text):
    """读取订阅文本返回uri列表"""
    node_list = []
    for i in decode_base64(text).split('\n'):
        if len(i) >= 10:
            node_list.append(i)
    return node_list


def list_to_subscribe(nodes_list):
    """读取节点列表转换为订阅文本"""
    buff = ''
    for i in nodes_list:
        buff = buff + i + '\n'
    buff = buff.strip()
    # print(buff)
    return encode_base64(buff)


def node_encoder(proxies_dict):
    if proxies_dict['type'] == "ss":
        url = ss_encode(proxies_dict)
    elif proxies_dict['type'] == "vmess":
        url = vmess_encode(proxies_dict)
    elif proxies_dict['type'] == "trojan":
        url = trojan_encode(proxies_dict)
    else:
        return False
    return url


if __name__ == '__main__':
    # print(decode_base64('YWVzLTI1Ni1nY206WTZSOXBBdHZ4eHptR0M'))
    # uri = 'ss://YWVzLTI1Ni1nY206WTZSOXBBdHZ4eHptR0M@134.195.196.187:5001#%e6%ac%a7%e6%b4%b2(%e6%ac%a2%e8%bf%8e%e8%ae%a2%e9%98%85Youtube%e7%a0%b4%e8%a7%a3%e8%b5%84%e6%ba%90%e5%90%9b)'
    # ss_decode(uri)
    my_uri = 'trojan://e8c1ab3c-89b3-4933-92df-682e6dce7819@jgwxn4.gaox.ml:443?security=tls&type=tcp&headerType=none#%e7%be%8e%e5%9b%bd(%e6%ac%a2%e8%bf%8e%e8%ae%a2%e9%98%85Youtube%e7%a0%b4%e8%a7%a3%e8%b5%84%e6%ba%90%e5%90%9b)'
    my_dict = {'name': '🇷🇺 俄罗斯(欢迎订阅Youtube破解资源君)', 'server': 'us.456url.com', 'port': 10086, 'type': 'trojan',
               'password': 'fbd77250-a674-4a24-be1a-d1a76f695c34', 'skip-cert-verify': False}
    my_dict1 = {'name': '加拿大(欢迎订阅Youtube破解资源君) 24', 'server': 'ca-trojan.bonds.id', 'port': 443, 'type': 'trojan',
                'password': 'bc7593fe-0604-4fbe-a70bYWVzLTI1Ni1nY206Q1VuZFNabllzUEtjdTaclWNFc1RmRBNk5NQU5KSnga3fa58ac5a3ef0-b4ab-11eb-b65e-1239d0255272',
                'sni': 'ca-trojan.bonds.id', 'skip-cert-verify': True, 'udp': True}

    print(trojan_encode(my_dict1))
    # print(trojan_decode(my_uri))
    pass
