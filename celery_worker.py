
#my worker 4 make new info from exp_API
import os
import sys
import json
import redis

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import celeryConfig
from celery import Celery
import time
import requests



POSTGRES = {
    'user': 'postgres',
    'pw': 'P@ssword',
    'host': 'localhost',
    'port': '5432',
}

app = Celery('celerySender')
app.config_from_object(celeryConfig)

#data = {"name":"rozbeh","number":"12345"}
redisdb = redis.StrictRedis(host = 'my_demo_app_db', port = '6379', db = '3')
headers = {"Content-Type":"application/json"}

@app.task(name = "Infosender")
def getWebCelery(data, method='POST', timeout=2):
    try:
        BASE_URL = 'http://my-app-makedataapi/make'
        st = time.time()
        url = f'{BASE_URL}'
        print("im in celery....\n")
        res = requests.request(method.upper(), f'{url}', headers = headers, data = data)
        load_time = time.time() - st
        load_time = round(load_time, 1)
        res.raise_for_status()
        res_json = res.json()
        res_json_f = json.dumps(res_json)
#        redisdb.set(str(key), res_json_f)
        print(key)
        print('\n')
        dd = redisdb.get(str(key))
        print(dd)
    except requests.exceptions.Timeout as e:
        return 408, "timeout exception"
    except requests.HTTPError as e:
        return -1, "Failed to get fund status from MFR API: {}".format(str(e.errno))
    except Exception as e:
        return -2, e.args[0]
    return 200, load_time


@app.task(name = "Infodump")
def getDataCelery(data, method='POST', timeout=2):
    try:

        BASE_URL = 'http://my-app-getdataapi/getdata'
        headers = {"Content-Type":"application/json"}
        st = time.time()
        url = f'{BASE_URL}'
        res = requests.request(method.upper(), f'{url}', headers = headers, data = data)
        load_time = time.time() - st
        load_time = round(load_time, 1)
        res.raise_for_status()
        res_json = res.json()
        res_json_f = str(json.dumps(res_json))
        localdb = redis.StrictRedis(host = 'my_celery_db', port = '6379', db = '1')
        localdb.set(str(key), res_json_f)
    except requests.exceptions.Timeout as e:
        return 408, "timeout exception"
    except requests.HTTPError as e:
        return -1, "Failed to get fund status from MFR API: {}".format(str(e.errno))
    except Exception as e:
        return -2, e.args[0]
    return 200, load_time


