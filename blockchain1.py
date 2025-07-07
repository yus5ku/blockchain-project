import contextlib
import hashlib
import json
import logging
import sys
import time
import threading
import requests

from ecdsa import NIST256p
from ecdsa import VerifyingKey

import utils

MINING_DIFFICULTY = 3
MINING_SENDER = 'THE BLOCKCHAIN'
MINING_REWARD = 1.0
MINING_TIMER_SEC =20

BLOCKCHAIN_PORT_RANGE = (5002,5004)
NEIGHBOURS_IP_RANGE_NUM =(0,1)
BLOCKCHAIN_NEIGHBOURS_SYNC_TIME_SEC = 20

logging.basicConfig(level=logging.INFO,stream=sys.stdout)
logger = logging.getLogger(__name__)

class BlockChain(object):

    def __init__(self, blockchain_address=None, port=None, ports=None):
        self.transaction_pool = []
        self.chain = []
        self.neighbours = []
        self.blockchain_address = blockchain_address 
        self.port = port
        self.ports = ports or []
        host = utils.get_host()
        for p in self.ports:
            if p == self.port:
                continue
            if utils.is_found_host(host, p):
                self.neighbours.append(f"{host}:{p}")
        logger.info({'action':'set_neighbours','neighbors':self.neighbours})
        self.create_block(0,self.hash({}))
        self.mining_semaphone = threading.Semaphore(1)
        self.sync_neighbours_smaphore = threading.Semaphore(1)

    def run(self):
        self.sync_neighbours()
        self.resolve_conflicts()
        #self.start_mining()


    def set_neighbours(self):
        self.neighbours = utils.find_neighbours(
            utils.get_host(), self.port,
            NEIGHBOURS_IP_RANGE_NUM[0], NEIGHBOURS_IP_RANGE_NUM[1],
            BLOCKCHAIN_PORT_RANGE[0], BLOCKCHAIN_PORT_RANGE[1])
        logger.info({'action':'set_neighbours','neighbors':self.neighbours})

    def sync_neighbours(self):
        is_acquire = self.sync_neighbours_smaphore.acquire(blocking=False)
        if is_acquire:
            with contextlib.ExitStack() as stack:
                stack.callback(self.sync_neighbours_smaphore.release)
                self.set_neighbours()
                # ブロックチェーンを同期
                self.sync_blockchain()
                loop = threading.Timer(BLOCKCHAIN_NEIGHBOURS_SYNC_TIME_SEC,self.sync_neighbours)
                loop.start()
    
    def sync_blockchain(self):
        """他のノードからブロックチェーンを同期"""
        for node in self.neighbours:
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    received_chain = response.json()['chain']
                    if len(received_chain) > len(self.chain):
                        self.chain = received_chain
                        logger.info({'action': 'sync_blockchain', 'status': 'updated', 'node': node})
            except Exception as e:
                logger.error({'action': 'sync_blockchain', 'error': str(e), 'node': node})
        
    
    def create_block(self,nonce,previous_hash):
        block = utils.sorted_dict_by_key({
            'timestamp':time.time(),
            'transactions':self.transaction_pool,
            'nonce':nonce,
            'previous_hash':previous_hash
        })
        self.chain.append(block)
        self.transaction_pool = []

        for node in self.neighbours:
            requests.delete(f'http://{node}/transactions')
            # ブロックチェーンを同期
            requests.put(f'http://{node}/chain', json={'chain': self.chain})
        return block
    
    def hash(self, block):
        sorted_block = json.dumps(block, sort_keys=True)
        return hashlib.sha256(sorted_block.encode()).hexdigest()
    
    def add_transaction(self,sender_blockchain_address,recipient_blockchain_address,value,
                        sender_public_key=None, signature=None):
         transaction = utils.sorted_dict_by_key({
              'sender_blockchain_address' :sender_blockchain_address,
              'recipient_blockchain_address' :recipient_blockchain_address,
              'value' :float(value)
         })
         
         if sender_blockchain_address == MINING_SENDER:
             self.transaction_pool.append(transaction)
             return True

         
         if self.verify_transaction_signature(
             sender_public_key, signature, transaction):
            
            #if self.calculate_total_amount(sender_blockchain_address) < float(value):
            #    logger.error({'action':'add_transaction','error':'no_value'})
            #    return False

            self.transaction_pool.append(transaction)
            return True
         return False
    
    def create_transaction(self, sender_blockchain_address,recipient_blockchain_address,
                           value,sender_public_key=None, signature=None):
        
        is_transacted =self.add_transaction(
            sender_blockchain_address,recipient_blockchain_address,value
            ,sender_public_key,signature)
        
        if is_transacted:
            for node in self.neighbours:
                requests.put(
                    f'http://{node}/transactions',
                    json={
                        'sender_blockchain_address':sender_blockchain_address,
                        'recipient_blockchain_address':recipient_blockchain_address,
                        'value':value,
                        'sender_public_key':sender_public_key,
                        'signature':signature,
                    }
                )

        #Sync
        for node in self.neighbours:
            requests.put(
                f'http://{node}/transactions',
                json={
                    'sender_blockchain_address':sender_blockchain_address,
                    'recipient_blockchain_address':recipient_blockchain_address,
                    'value':value,
                }
            )
        return is_transacted

    def verify_transaction_signature(
            self,sender_public_key,signature, transaction):
        sha256 = hashlib.sha256()
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()
        signature_bytes = bytes().fromhex(signature)
        Verifying_Key = VerifyingKey.from_string(
            bytes().fromhex(sender_public_key),curve=NIST256p)
        verified_Key = Verifying_Key.verify(signature_bytes, message)
        return verified_Key

    def valid_proof(self, transactions, previous_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess_block = utils.sorted_dict_by_key({
            'transactions' : transactions,
            'nonce' : nonce,
            'previous_hash' : previous_hash
        })
        guess_hash = self.hash(guess_block)
        return guess_hash[:difficulty] == '0'*difficulty


    def proof_of_work(self):
        transactions = self.transaction_pool.copy()
        previous_hash = self.hash(self.chain[-1])
        nonce = 0
        while self.valid_proof(transactions, previous_hash, nonce) is False:
            nonce += 1
        return nonce

    def mining(self):
        # マイニング報酬のトランザクションを追加
        self.add_transaction(
                sender_blockchain_address=MINING_SENDER,
                recipient_blockchain_address=self.blockchain_address,
                value=MINING_REWARD)
        nonce = self.proof_of_work()
        previous_hash = self.hash(self.chain[-1])
        self.create_block(nonce,previous_hash)
        logger.info({'action':'mining','status':'success'})

        for node in self.neighbours:
            requests.put(f'http://{node}/consensus')

        return True

    
    def start_mining(self):
        is_acquire = self.mining_semaphone.acquire(blocking=False)
        if is_acquire:
            with contextlib.ExitStack() as stack:
                stack.callback(self.mining_semaphone.release)
                self.mining()
                loop = threading.Timer(MINING_TIMER_SEC, self.start_mining)
                loop.start()
    
    def calculate_total_amount(self, blockchain_address):
        total_amount = 0.0
        for block in self.chain:
            for transaction in block['transactions']:
                value = float(transaction['value'])
                if blockchain_address == transaction['recipient_blockchain_address']:
                    total_amount += value
                if blockchain_address == transaction['sender_blockchain_address']:
                    total_amount -= value
        return total_amount


    def valid_chain(self, chain):
        pre_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(pre_block):
                return False
            if not self.valid_proof(
                block['transactions'],
                block['previous_hash'],
                block['nonce'], MINING_DIFFICULTY):
                return False
            pre_block = block
            current_index += 1
        return True


    def resolve_conflicts(self):
        longest_chain = None
        max_length = len(self.chain)
        for node in self.neighbours:
            response = requests.get(f'http://{node}/chain')
            if response.status_code == 200:
                response_json = response.json()
                chain = response_json['chain']
                chain_length = len(chain)
                if chain_length > max_length and self.valid_chain(chain):
                    max_length = chain_length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            logger.info({'action':'resolve_conflicts','status':'replaced'})
            return True
        logger.info({'action':'resolve_conflicts','status':'not_replaced'})
        return False

