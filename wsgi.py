#!/usr/bin/env python3
# wsgi.py

from flask import Flask, request, jsonify
import db

app = Flask(__name__)


@app.route("/")
def list_switches():
    return jsonify(db.sw_list())


@app.route("/<sw_ip>", methods=['GET', 'POST', 'DELETE'])
def sw_ops(sw_ip):
    r = request.method.lower().replace('post', 'add')
    result = eval(f'db.sw_{r}(sw_ip)')
    return jsonify(result)
