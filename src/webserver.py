import sys
import argparse
import logging
import collections
from flask import Flask
from flask_basicauth import BasicAuth
from flask import jsonify
import redis

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

# CLI args
parser = argparse.ArgumentParser(description='Monitor CT logs for interesting domains')

parser.add_argument('--web-port', type=int, default=8080, help='Webserver listen port')
parser.add_argument('--web-host', default='0.0.0.0', help='Webserver listen IP')
parser.add_argument('--web-password', default='sniffer', help='HTTP Basic Auth password to access the web interface')
parser.add_argument('--web-username', default='cert', help='HTTP Basic Auth username to access the web interface')
parser.add_argument('--redis-host', default='redis', help='Redis hostname')
parser.add_argument('--redis-password', default='certstream', help='Redis password')
parser.add_argument('--redis-port', type=int, default=6379, help='Redis port')


args = parser.parse_args()

buffer = collections.deque(maxlen=500)

app = Flask(__name__)
app.config['BASIC_AUTH_USERNAME'] = args.web_username
app.config['BASIC_AUTH_PASSWORD'] = args.web_password

basic_auth = BasicAuth(app)

redis_db = redis.StrictRedis(host=args.redis_host, port=args.redis_port, db=0, password=args.redis_password)
try:
    response = redis_db.client_list()
except redis.ConnectionError:
    logging.fatal('Unable to connect to Redis server')
    sys.exit(1)

@app.route('/get-domains')
@basic_auth.required
def get_domains():

    response = []
    domain_keys = redis_db.keys(pattern='domain:*')
    for domain_key in domain_keys:
        response.append({
            'domain': redis_db.get(domain_key).decode('utf-8')
        })

    return jsonify(response)

@app.route('/')
def index():
    return jsonify({'description':'You know, for CT sniffing'})


if __name__ == '__main__':

    logging.info('Starting webserver...')
    app.run(host=args.web_host, port=args.web_port)
