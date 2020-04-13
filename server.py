import sqlite3
import multiprocessing
import time
from flask import Flask, make_response, g, abort, request, jsonify
import json
from celery import Celery
import mysql.connector
import argparse

# Setting flask and celery connected to rabbitmq
app = Flask(__name__)

app.config['CELERY_BROKER_URL'] = 'amqp://guest:guest@localhost:5672'
app.config['CELERY_RESULT_BACKEND'] = 'amqp://guest:guest@localhost:5672'

celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

vms = []
fw_rules = []
attack_surface = []

##################################################
# Dynamic app config
##################################################


def app_config(cfg):
    """simple function to configure app from command line args"""
    app.config['ARCH'] = cfg.arch  # THREADBASED/QUEUEBASED/NAIVE
    app.config['DB'] = cfg.db  # MYSQL/SQLITE
    if app.config['DB'] == 'MYSQL':
        app.config['SQL_SCHEME'] = 'schemaMYSQL.sql'
        app.config['DB_CONF'] = {'host': "localhost",
                                 'user': "guest",
                                 'passwd': "guest",
                                 'database': "as_servicedb"}
    elif app.config['DB'] == 'SQLITE':
        app.config['SQL_SCHEME'] = 'schemaSQLITE.sql'
        app.config['DB_CONF'] = {'database': "AS_serviceDB.db"}
    else:
        pass
    celery.conf.update(app.config)

##################################################
# Celery tasks
##################################################


@celery.task
def background_stat_store(duration):
    """this tasks asynchroniously saves request processsing duretion to mysql db"""
    add_stat_to_db(duration)


##################################################
# JSON architecture input processing
##################################################


def read_input(input_file):
    """simple function to read input files"""
    with open(input_file, 'r') as jf:
        data = json.load(jf)
    return data


def process_input(input_json):
    """simple function to process input json to attack map"""

    # go through all machines and collect all tags. Build tag dict with mashine sets as keys
    machine_tag_dict = {}
    for m in input_json['vms']:
        for t in m['tags']:
            if not t in machine_tag_dict:
                machine_tag_dict[t] = set()
            machine_tag_dict[t].add(m['vm_id'])

    # go through all firwall rules and construct tag attack surface
    tag_attack_surface = {}
    for r in input_json['fw_rules']:
        source = r['source_tag']
        dest = r['dest_tag']
        if not dest in tag_attack_surface:
            tag_attack_surface[dest] = set()
        tag_attack_surface[dest].add(source)
    # go through all machines again and determine attack map using tag attack map
    attack_map = {}
    for m in input_json['vms']:
        attacker_machines = set()
        for tag in m['tags']:
            if tag in tag_attack_surface:
                for attacker_tag in tag_attack_surface[tag]:
                    if attacker_tag in machine_tag_dict:
                        attacker_machines.update(
                            machine_tag_dict[attacker_tag])
        try:
            attacker_machines.remove(m['vm_id'])
        except:
            pass
        attack_map[m['vm_id']] = list(attacker_machines)

    return attack_map

##################################################
# DB related operations
##################################################


def get_db():
    """returns a db connection based of database configuration of the application"""
    if app.config['DB'] == 'MYSQL':
        db = mysql.connector.connect(**app.config['DB_CONF'])
    elif app.config['DB'] == 'SQLITE':
        db = sqlite3.connect(app.config['DB_CONF']['database'])
    else:
        db = None
    return db


def init_db():
    """simple function to init db from schema"""
    try:
        db = get_db()
        with open(app.config['SQL_SCHEME'], mode='r') as f:
            if app.config['DB'] == 'SQLITE':
                db.cursor().executescript(f.read())
            elif app.config['DB'] == 'MYSQL':
                res = db.cursor().execute(f.read(), multi=True)
                for r in res:
                    print(r)
            else:
                pass
        db.commit()
        print('the db was initiated successfuly')
    except:
        print('failed to initiate the db')


def get_stats_from_db():
    """simple functions to retrieve number of requests processed and average request processing time"""
    try:
        db = get_db()
        query = 'select count(id), avg(duration) from stats'
        cur = db.cursor()
        cur.execute(query)
        stats = cur.fetchall()[0]
        # print(stats)
        db.close()
        return stats
    except Exception as e:
        print(e)
        print('failed to retrieve stat from db')
        return (0, None)


def add_stat_to_db(duration):
    """ Add a stat to the db. """
    try:
        db = get_db()
        if app.config['DB'] == 'MYSQL':
            sql = ''' INSERT INTO stats(duration) VALUES(%s) '''
        else:
            sql = ''' INSERT INTO stats(duration) VALUES(?) '''
        cur = db.cursor()
        cur.execute(sql, (duration,))
        db.commit()
        db.close()
    except Exception as e:
        print(e)
        print('error: failed to save stat to DB for this request')

#################################
# Flask server specific section
#################################


@app.before_request
def start_counter():
    """this is used to start request processing time counter"""
    # start counter
    g.start_time = time.time()


@app.teardown_request
def stop_counter(error=None):
    """this is used to stop request processing time counter and spawn a thread that will save this result to db
    Note: ideally this should be done with proper task queue instead of thread spawning """
    # measure delta
    delta = time.time() - g.start_time
    # print(delta)
    # add_stat_to_db(delta)
    try:
        if app.config['ARCH'] == 'THREADBASED':
            thread = multiprocessing.Process(
                target=add_stat_to_db, args=(delta,))
            thread.start()
        elif app.config['ARCH'] == 'QUEUEBASED':
            print('celery')
            background_stat_store.delay(delta)
        else:
            add_stat_to_db(delta)
    except:
        print('error: failed to spawn stat dump for this request')


@app.errorhandler(500)
def server_error(error=None):
    """Server error handler."""
    return make_response({'description': 'internal server error'}, 500)


@app.errorhandler(405)
def method_not_allowed(error=None):
    """Method not allowed handler."""
    return make_response({'description': 'method not allowed'}, 405)


@app.route("/api/v1/attack", methods=['GET'])
def get_attack_surface():
    """function to return attack surface of machine vm_id in json form"""
    # handle bad request
    vm_id = request.args.get('vm_id', None)
    if vm_id is None:
        abort(400, description="vm_id is missing")

    # get attack surface data from initialized python dict
    data = attack_surface.get(vm_id, None)
    # handle not found machine request (should it be 404? not sure)
    if data is None:
        abort(404, description="vm_id not found")

    response = make_response(jsonify(data), 200)
    response.headers = {"Content-Type": "application/json"}
    return response


@app.route("/api/v1/stats", methods=['GET'])
def get_statistics():
    """function to return serice statistics in json form"""
    # retrieve statistics from db
    stats = get_stats_from_db()
    # get number of virtual machines from initiated pthon object
    vm_count = len(vms)

    # return statistics
    statistics = {'vm_count': vm_count, 'request_count': stats[0],
                  'average_request_time': stats[1]}
    response = make_response(statistics, 200)
    response.headers = {"Content-Type": "application/json"}

    return response


if __name__ == '__main__':
    # 0. parse args
    # 1. init empty db
    # 2. read input file
    # 3. produce attack_surface dict
    # 4. start the app

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--db", type=str, default='SQLITE', choices=['SQLITE', 'MYSQL'],
                        help="database to use - MYSQL or SQLITE")
    parser.add_argument("-i", "--input", type=str, default='data/input-0.json',
                        help="System architecture in json format")
    parser.add_argument("-a", "--arch", type=str, choices=['NAIVE', 'THREADBASED', 'QUEUEBASED'],
                        default='NAIVE', help="Server db save model")
    cfg = parser.parse_args()

    app_config(cfg)

    init_db()
    data = read_input(cfg.input)
    attack_surface = process_input(data)
    try:
        vms = data['vms']
        fw_rules = data['fw_rules']
    except:
        vms = []
        fw_rules = []

    app.run()
