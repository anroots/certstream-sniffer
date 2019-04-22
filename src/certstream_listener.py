import sys
import hashlib
import argparse
import logging
import tldextract
import collections
import certstream
import redis

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

# CLI args
parser = argparse.ArgumentParser(description='Monitor CT logs for interesting domains')

parser.add_argument('--tld', action='append', nargs='?', default=[],
                    help='Include this TLD (.com) into results')
parser.add_argument('--redis-host', default='redis', help='Redis hostname')
parser.add_argument('--redis-password', default='certstream', help='Redis password')
parser.add_argument('--redis-port', type=int, default=6379, help='Redis port')
parser.add_argument('--expire-time', type=int, default=300, help='How many seconds to remember found domains')


args = parser.parse_args()

buffer = collections.deque(maxlen=500)

redis_db = redis.StrictRedis(host=args.redis_host, port=args.redis_port, db=0, password=args.redis_password)

try:
    response = redis_db.client_list()
except redis.ConnectionError:
    logging.fatal('Unable to connect to Redis server')
    sys.exit(1)


def new_cert(message, context):
    if message['message_type'] != "certificate_update":
        return

    # Set removes duplicate domains
    all_domains = set(message['data']['leaf_cert']['all_domains'])

    for domain in all_domains:
        domain_parts = tldextract.extract(domain)

        if len(args.tld) and domain_parts.suffix not in args.tld:
            continue

        if domain_parts.subdomain == '*':
            domain = '{}.{}'.format(domain_parts.domain, domain_parts.suffix)

        # Do not insert duplicates
        if domain in buffer:
            continue
        buffer.append(domain)

        # 'domain:1bf2a387578214393c38e134d35f2f0af65e2d44bf77478d66dc6a5d284ce9b1'
        db_key = 'domain:{}'.format(hashlib.sha256(domain.encode()).hexdigest())
        redis_db.set(db_key, domain, args.expire_time)
        logging.debug('Found domain %s', domain)


if __name__ == '__main__':

    logging.info('Starting certstream listener...')
    certstream.listen_for_events(new_cert, "wss://certstream.calidog.io")
