# -*- coding: utf-8 -*-
from flask import Flask, render_template, \
    request, jsonify,make_response, Markup
import re
import requests
import json
import socket
from .pocdata import *

app = Flask(__name__)


def getjson():
    return json.loads(request.get_data().decode("utf-8"))


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/getdomain')
def getdomin():
    return render_template('getdomain.html', title='旁站/C段')


@app.route('/information')
def information_scan():
    return render_template('information.html', title='信息泄露', data=Markup(list(informationpocdict.keys())))


@app.route('/portscan')
def portcan():
    return render_template('/portscan.html', title='端口扫描')

@app.route('/base64')
def base64_decode():
    return render_template('/base64.html', title='Base64')

@app.route('/morse')
def morse_ed():
    return render_template('/morse.html', title='摩斯电码')

@app.route('/caesar')
def carsar_decode():
    return render_template('/caesar.html', title='凯撒密码')

@app.route('/md5')
def md5_encode():
    return render_template('/md5.html', title='MD5')

@app.route('/urls')
def url_s():
    return render_template('/urls.html', title='目录探测')

@app.route('/test')
def test_test():
    return render_template('test.html', title='test')
'''

api定义段

'''


# webscan.cc结果查询
@app.route('/api/query', methods=['post'])
def query_c():
    post_json = getjson()
    request_json_raw = requests.get('http://www.webscan.cc/?action=query&ip=%s' % post_json[0]['ip'])
    return request_json_raw.content


# 结果下载
@app.route('/api/download', methods=['POST'])
def download_file():
    content = request.form.get("save")
    response = make_response(content.replace("|", "\n"))
    response.headers['Content-Disposition'] = 'attachment; filename=data.txt'
    return response


# domain2ip
@app.route('/api/domain2ip', methods=['POST'])
def return_json():
    domain_json = getjson()
    ip = socket.gethostbyname(domain_json[0]['domain'].split('/')[2])
    j_ip = [{"ip": ip}]
    return jsonify(j_ip)


# thread_start
@app.route('/api/thread', methods=['post'])
def thread_start():
    thread_ip = getjson()
    thread_json_raw = requests.get('http://webscan.cc/thread.php?ip=%s' % thread_ip[0]['ip'])
    return thread_json_raw.content


# 信息泄露
@app.route('/api/information', methods=['post'])
def information_api():
    information_load = getjson()
    information_url = information_load['url']
    information_type = information_load['type']
    information_poc_result = list(informationpocdict.values())[information_type](information_url).run()
    if "[+]" in information_poc_result:
        information_poc_status = 1
    else:
        information_poc_status = 0
    return jsonify({"status": information_poc_status, "pocresult": information_poc_result})

# 端口扫描
@app.route('/api/portscan', methods=['post'])
def portsan_api():
    ip_port_json = getjson()
    ip = ip_port_json["ip"]
    port = ip_port_json["port"]
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(1)
    try:
        sk.connect((ip, port))
        return jsonify({"ip": ip, "port": port, "status": 1})
    except Exception:
        return jsonify({"ip": ip, "port": port, "status": 0})

    