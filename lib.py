import node_lib
import requests
import yaml
import re
import json


class Config:
    """设置类"""

    def __init__(self, config_path='config.json'):
        self.config_path = config_path
        self.backup_path = config_path + '.bak'

    def load_config(self):
        """读取配置"""
        config_f = open(self.config_path, 'r+', encoding='utf-8')
        config = json.load(config_f)
        return config

    def __backup_config(self):
        """备份配置"""
        config = self.load_config()
        f_config = open(self.backup_path, 'w+', encoding='utf-8')
        json.dump(config, f_config, ensure_ascii=False)

    def save_config(self, new_config):
        """保存配置"""
        self.__backup_config()
        new_config = json.dumps(new_config, ensure_ascii=False)
        config_f = open(self.config_path, 'w+', encoding='utf-8')
        config_f.write(new_config)


def read_nodes(nodes_path):
    """读取节点数据，返回节点列表"""
    f = open(nodes_path, 'r', encoding='utf-8')
    buff = f.read().strip().split('\n')
    f.close()
    return buff


def nodes_deduplication(nodes_list):
    """uri格式节点去重"""
    config1 = Config()
    nodes_path = config1.load_config()['NODES_PATH']
    f_nodes = open(nodes_path, 'r', encoding='utf-8')
    data_list = f_nodes.read().strip().split('\n')
    data_list_len = len(data_list)
    for i in nodes_list:
        if i[:5] == 'ss://':
            if node_lib.check_ss(data_list, i) == 0:
                # print('nodes_list append {}'.format(i))
                data_list.append(i)
        elif i[:8] == 'vmess://':
            # print(i)
            if node_lib.check_vmess(data_list, i) == 0:
                # print('nodes_list append {}'.format(i))
                data_list.append(i)
        elif i[:9] == 'trojan://':
            if node_lib.check_trojan(data_list, i) == 0:
                # print('nodes_list append {}'.format(i))
                data_list.append(i)
    f_nodes.close()
    f_nodes_w = open(nodes_path, 'w+', encoding='utf-8')
    for i in data_list:
        if len(i) >= 10:
            f_nodes_w.write(i + '\n')
    return [data_list_len, len(data_list), len(data_list) - data_list_len]


def sub_to_data(sub_buff):
    """读取订阅内容sub_text，节点去重后写入nodes.txt"""
    nodes_list = node_lib.subscribe_to_list(sub_buff)
    return nodes_deduplication(nodes_list)


def clash_to_data(yml_buff):
    """读取clash配置内容提取节点，写入nodes.txt"""
    nodes_list = []
    yml_buff = yml_buff.replace('!<str>', '')
    buff = yaml.safe_load(yml_buff)
    nodes = buff['proxies']
    for i in nodes:
        if i['type'] == 'ss':
            nodes_list.append(node_lib.ss_encode(i))
        elif i['type'] == 'vmess':
            nodes_list.append(node_lib.vmess_encode(i, flag='base64'))
        elif i['type'] == 'trojan':
            nodes_list.append(node_lib.trojan_encode(i))
    return nodes_deduplication(nodes_list)


def sub_file_to_data(sub_file):
    """读取订阅文件sub_text，节点去重后写入nodes.txt"""
    f = open(sub_file)
    sub_text = f.read()
    sub_to_data(sub_text)


def clash_file_to_data(clash_yml):
    """读取clash配置文件提取节点"""
    fs = open(clash_yml, encoding='utf-8')
    clash_to_data(fs)


def is_base64(base64str):
    """判断是否是base64编码，不是返回None"""
    r = re.match(r'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$', base64str)
    if r is None:
        return 0
    else:
        return 1


def get_to_data(url):
    """读取在线内容（支持订阅和clash），写入nodes.txt"""
    buff = requests.get(url).content
    try:
        is64 = is_base64(buff.decode('utf-8-sig'))
        if is64 == 0:
            return clash_to_data(buff.decode('utf-8'))
        else:
            # print(buff.decode('utf-8'))
            return sub_to_data(buff.decode('utf-8-sig'))
    except Exception as error:
        raise error


if __name__ == '__main__':
    sub_url = 'https://ghproxy.com/https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/0702clash.yml'
    sub_url2 = 'https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/0322.txt'
    get_to_data(sub_url)
    pass
