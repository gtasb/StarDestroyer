# 审计引擎验收用的靶子：故意保留漏洞，不要在生产使用。
# FIXTURE ONLY - intentionally vulnerable.
import os
import pickle
import requests
import subprocess


def search(cur, request):
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cur.execute(query)


def deserialize(request):
    data = request.get_data()
    return pickle.loads(data)


def fetch(request):
    url = request.args.get("url")
    return requests.get(url)


def ping(request):
    host = request.args.get("host")
    subprocess.run("ping -c 1 " + host, shell=True)


def safe(cur, request):
    name = request.args.get("name")
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
