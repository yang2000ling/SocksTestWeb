import lib
import node_lib

config1 = lib.Config()
config = config1.load_config()


def read_nodes():
    buff = lib.read_nodes(config['NODES_PATH'])
    nodes_list = []
    for n in buff:
        node = node_lib.node_decoder(n)
        nodes_list.append(node)
    return nodes_list


def read_output():
    buff = open(config['OUTPUT_PATH'], 'r', encoding='utf-8').read()
    uri_list = node_lib.decode_base64(buff).strip().split('\n')
    output_list = []
    for i in uri_list:
        output_list.append(node_lib.node_decoder(i))
    return output_list


def output_urls():
    f = open(config['NODES_PATH'], 'r', encoding='utf-8')
    return f.read()


if __name__ == '__main__':
    nodes = read_nodes()
    print(nodes)
    # urls = output_urls()
    pass