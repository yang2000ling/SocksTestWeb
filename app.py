from flask import Flask
from flask import render_template
from flask import request
import fun
import lib

app = Flask(__name__)


@app.route('/')
@app.route('/index')
def index():  # put application's code here
    return render_template('index.html')


@app.route('/get_url', methods=['POST'])
def get_url():  # put application's code here
    if request.method == 'POST':
        url = request.form['url']
        ghproxy = request.form['ghproxy']
        if ghproxy == 'true' and url.find('https://ghproxy.com/') == -1:
            url = 'https://ghproxy.com/' + url
            print(url)
        try:
            re = lib.get_to_data(url)
            print(re)
            return render_template('index.html', url=url, info=re)
        except Exception as error:
            print('error:', error)
            return render_template('index.html', url=url, error=error)
    return render_template('index.html')


@app.route('/nodes_list')
def nodes_list():  # put application's code here
    try:
        nodes = fun.read_nodes()
        urls = fun.output_urls()
        print(urls)
        return render_template('node_list.html', nodes_list=nodes, output_url=urls)
    except Exception as error:
        return render_template('node_list.html', error=error)


@app.route('/output_list')
def output_list():
    try:
        config1 = lib.Config()
        config = config1.load_config()
        nodes = fun.read_output()
        return render_template('node_list.html', nodes_list=nodes)
    except Exception as error:
        return render_template('node_list.html', error=error)


@app.route('/config', methods=['POST', 'GET'])
def config_page():
    error = None
    config1 = lib.Config()
    config = config1.load_config()
    if request.method == 'POST':
        new_config = {"NODES_PATH": request.form['nodes-path'], "OUTPUT_PATH": request.form['output-path']}
        print(new_config)
        config1.save_config(new_config)
        config = config1.load_config()
        return render_template('config.html', error=error, config=config)
    return render_template('config.html', config=config)


if __name__ == '__main__':
    app.run()
