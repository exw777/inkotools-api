#!/usr/bin/env python3
# app.py

from flask import Flask, request
import db

app = Flask(__name__)


@app.route("/")
def list_switches():
    return str(db.sw_list())


@app.route("/<sw_ip>", methods=['GET', 'POST', 'DELETE'])
def sw_ops(sw_ip):
    if request.method == 'POST':
        result = db.sw_upsert(sw_ip)
    elif request.method == "GET":
        result = db.sw_get(sw_ip)
    elif request.method == "DELETE":
        result = db.sw_delete(sw_ip)
    return str(result)
