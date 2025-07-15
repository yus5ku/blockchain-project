from flask import Flask
from flask import jsonify
import time
from flask import request
from argparse import ArgumentParser
import multiprocessing

import blockchain1
import wallet

app = Flask(__name__)

cache = {}
cache['blockchain'] = blockchain1.BlockChain()

#def get_blockchain():
    if 'blockchain' in cache:
        return cache['blockchain']
    else:
        # 初期化やエラー処理
        miners_wallet = wallet.Wallet()
        cached_blockchain = blockchain1.BlockChain(
            blockchain_address=miners_wallet.blockchain_address,
            port=app.config['port'])
        app.logger.warning({
            'private_key' : miners_wallet.private_key,
            'public_key' : miners_wallet.public_key,
            'blockchain_address': miners_wallet.blockchain_address,
            'timestamp': time.time()
        })
        return cache['blockchain']

@app.route('/chain', methods=['GET'])
def get_chain():
    block_chain = get_blockchain()
    response = {
        'chain': block_chain.chain
    }
    return jsonify(response), 200

@app.route('/transactions', methods=['GET','POST','PUT','DELETE'])
def transaction():
    block_chain = get_blockchain()
    if request.method == 'GET':
        transactions = block_chain.transaction_pool
        response = {
            'transactions': transactions,
            'length': len(transactions)
        }
        return jsonify(response), 200

    if request.method == 'POST':
        request_json = request.json
        required = (
            'sender_blockchain_address',
            'recipient_blockchain_address',
            'value',
            'sender_public_key',
            'signature'
        )
        if not all(k in request_json for k in required):
            return jsonify({'message': 'missing value'}), 400

        is_created = block_chain.create_transaction(
            request_json['sender_blockchain_address'],
            request_json['recipient_blockchain_address'],
            request_json['value'],
            request_json['sender_public_key'],
            request_json['signature'],
        )
        if not is_created:
            return jsonify({'message': 'fail'}), 400
        return jsonify({'message': 'success'}), 201
    
    if request.method == 'PUT':
        request_json = request.json
        required = (
            'sender_blockchain_address',
            'recipient_blockchain_address',
            'value',
            'sender_public_key',
            'signature'
        )
        if not all(k in request_json for k in required):
            return jsonify({'message': 'missing value'}), 400

        is_created = block_chain.create_transaction(
            request_json['sender_blockchain_address'],
            request_json['recipient_blockchain_address'],
            request_json['value'],
            request_json['sender_public_key'],
            request_json['signature'],
        )
        if not is_created:
            return jsonify({'message': 'fail'}), 400
        return jsonify({'message': 'success'}), 201

@app.route('/mine', methods=['GET'])
def mine():
    block_chain = get_blockchain()
    is_mined = block_chain.mining()
    if is_mined:
        return jsonify({'message': 'success'}), 200
    return jsonify({'message': 'fail'}), 400

@app.route('/mine/start', methods=['GET'])
def start_mine():
    get_blockchain().start_mining()
    return ('', 204)

@app.route('/amount', methods=['GET'])
def get_amount():
    blockchain_address = request.args.get('blockchain_address')
    if not blockchain_address:
        return jsonify({'message': 'Missing blockchain_address parameter'}), 400
    
    block_chain = get_blockchain()
    amount = block_chain.calculate_total_amount(blockchain_address)
    response = {
        'amount': amount
    }
    return jsonify(response), 200

def parse_ports(port_arg: str):
    """カンマ区切りで複数ポート指定可能"""
    return [int(p.strip()) for p in port_arg.split(',')]

def run_server(port: int):
    app.config['port']  = port
    app.config['ports'] = ports

    app.run(host='0.0.0.0', port=port, threaded=True, debug=True)

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument(
        '-p', '--port', default='5002', help='comma-separated list of ports to listen on, e.g. "5002,5003,5004"'
    )
    args = parser.parse_args()
    ports = parse_ports(args.port)

    get_blockchain().sync_neighbours()

    processes = []
    for port in ports:
        p = multiprocessing.Process(target=run_server, args=(port,))
        p.start()
        print(f'[INFO] Flask server started on port {port} (pid={p.pid})')
        processes.append(p)

    for p in processes:
        p.join()
