import collections
import logging
import re
import socket


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RE_IP = re.compile(r'(?P<prefix_host>^\d{1,3}\.\d{1,3}\.\d{1,3}\.)(?P<last_ip>\d{1,3}$)')

def sorted_dict_by_key(unsorted_dict):
    return collections.OrderedDict(sorted(unsorted_dict.items(), key=lambda d: d[0]))

def pprint(chains):
    for i, chain in enumerate(chains):
        print(f'{"="*25} Chain {i} {"="*25}')
        for k, v in chain.items():
            if k == 'transactions':
                print(k)
                for d in v:
                    print(f'{"-"*40}')
                    for kk, vv in d.items():
                        print(f'{kk:30}{vv}')
            else:
                print(f'{k:15}{v}')
    print(f'{"*"*25}')

def is_found_host(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((target, port))
            logger.info({
                'action': 'is_found_host',
                'target': target,
                'port': port,
                'result': 'success'
            })
            return True
        except Exception as ex:
            logger.info({
                'action': 'is_found_host', 
                'target': target,
                'port': port,
                'ex': str(ex)
            })
            return False

def find_neighbours(my_host, my_port, start_ip_range, end_ip_range, start_port, end_port):
    address = f'{my_host}:{my_port}'
    m = RE_IP.search(my_host)
    if not m:
        return []
    
    prefix_host = m.group('prefix_host')
    last_ip = m.group('last_ip')

    neighbours = []
    for guess_port in range(start_port, end_port+1):
        for ip_range in range(start_ip_range, end_ip_range):
            new_last_ip = int(last_ip) + int(ip_range)
            if new_last_ip > 255:
                continue
            guess_host = f'{prefix_host}{new_last_ip}'
            guess_address = f'{guess_host}:{guess_port}'
            if is_found_host(guess_host, guess_port) and guess_address != address:
                neighbours.append(guess_address)
    return neighbours

def get_host():
     try:
          return socket.gethostbyname(socket.gethostbyname())
     except Exception as ex:
         logger.debug({'action':'get_host','ex':ex})
     return '127.0.0.1'

#if __name__ == '__main__':
   #print(find_neighbours('10.160.177.134', 5002, 0, 3, 5002, 5005))
   #print(get_host())


if __name__ == '__main__':
    print(find_neighbours('192.168.3.15', 5002, 0, 3, 5002, 5005))
