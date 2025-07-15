import contextlib #コンテキストマネージャーをコンテキストマネージャーを簡単に扱う
import hashlib #ハッシュ関数を提供する
import json #JSONデータを扱う
import logging #ロギング機能を提供する
import sys #システム関連の機能を提供する
import time #時間関連の機能を提供する
import threading #スレッド関連の機能を提供する
import requests #HTTPリクエストを送信する

#ECDSAを使用して公開鍵と秘密鍵を生成する
from ecdsa import NIST256p
from ecdsa import VerifyingKey

import utils #ユーティリティ関数を提供する

#マイニングの難易度を設定する
MINING_DIFFICULTY = 3
MINING_SENDER = 'THE BLOCKCHAIN'
MINING_REWARD = 1.0
MINING_TIMER_SEC =20

#ブロックチェーンのポート範囲を設定する
BLOCKCHAIN_PORT_RANGE = (5002,5004)
#近隣ノードのIP範囲を設定する
NEIGHBOURS_IP_RANGE_NUM =(0,1)
#ブロックチェーンの近隣ノードの同期時間を設定する
BLOCKCHAIN_NEIGHBOURS_SYNC_TIME_SEC = 20

#ロギングの設定を行う
logging.basicConfig(level=logging.INFO,stream=sys.stdout)
logger = logging.getLogger(__name__)

#ブロックチェーンのクラスを定義する
class BlockChain(object):

    def __init__(self, blockchain_address=None, port=None, ports=None):
        #トランザクションプールを初期化する
        self.transaction_pool = []
        #ブロックチェーンを初期化する
        self.chain = []
        #近隣ノードを初期化する
        self.neighbours = []
        #ブロックチェーンのアドレスを設定する
        self.blockchain_address = blockchain_address 
        #ポートを設定する
        self.port = port
        #ポートを設定する
        self.ports = ports or []
        #ホストを取得する
        host = utils.get_host()
        #ポートを取得する
        for p in self.ports:
            #ポートが自分のポートと同じ場合はスキップする
            if p == self.port:
                continue
            #ポートが近隣ノードのポートと一致する場合は追加する
            if utils.is_found_host(host, p):
                self.neighbours.append(f"{host}:{p}")
        #近隣ノードを設定する
            logger.info({'action':'set_neighbours','neighbors':self.neighbours})
        #ブロックチェーンを作成する
        self.create_block(0,self.hash({}))
        #マイニングのセマフォを設定する
        self.sync_neighbours_smaphore = threading.Semaphore(1)

    #ブロックチェーンの実行を行う
    def run(self):
        #近隣ノードを同期する
        self.sync_neighbours()
        #競合を解決する
        self.resolve_conflicts()
        #マイニングを開始する
        self.start_mining()

    #近隣ノードを設定する
    def set_neighbours(self):
        self.neighbours = utils.find_neighbours(
            utils.get_host(), self.port,
            NEIGHBOURS_IP_RANGE_NUM[0], NEIGHBOURS_IP_RANGE_NUM[1],
            BLOCKCHAIN_PORT_RANGE[0], BLOCKCHAIN_PORT_RANGE[1])
        logger.info({'action':'set_neighbours','neighbors':self.neighbours})

    #近隣ノードを同期する
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
    
    #ブロックチェーンを同期する
        def sync_blockchain(self):
            for node in self.neighbours:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    received_chain = response.json()['chain']
                    #受信したブロックチェーンが自分のブロックチェーンより長い場合は更新する
                    if len(received_chain) > len(self.chain):
                        self.chain = received_chain
                        logger.info({'action': 'sync_blockchain', 'status': 'updated', 'node': node})
                else:
                    logger.error({'action': 'sync_blockchain', 'error': 'failed', 'node': node})
        
    
    #ブロックを作成する
    def create_block(self,nonce,previous_hash):
        block = utils.sorted_dict_by_key({
            'timestamp':time.time(),
            'transactions':self.transaction_pool,
            'nonce':nonce,
            'previous_hash':previous_hash
        })
        #ブロックを追加する
        self.chain.append(block)
        #トランザクションプールを初期化する
        self.transaction_pool = []
        #近隣ノードにブロックを送信する
        for node in self.neighbours:
            requests.delete(f'http://{node}/transactions')
            #ブロックチェーンを同期する
            requests.put(f'http://{node}/chain', json={'chain': self.chain})
        #ブロックを返す
        return block
    
    #ブロックのハッシュを計算する
    def hash(self, block):
        sorted_block = json.dumps(block, sort_keys=True)
        return hashlib.sha256(sorted_block.encode()).hexdigest()
    
    #トランザクションを追加する
    def add_transaction(self,sender_blockchain_address,recipient_blockchain_address,value,
                        sender_public_key=None, signature=None):
         transaction = utils.sorted_dict_by_key({
              'sender_blockchain_address' :sender_blockchain_address,
              'recipient_blockchain_address' :recipient_blockchain_address,
              'value' :float(value)
         })
         #マイニングの報酬を追加する
         if sender_blockchain_address == MINING_SENDER:
             self.transaction_pool.append(transaction)
             #トランザクションを追加する
             return True
         #トランザクションの署名を検証する
         if self.verify_transaction_signature(
             sender_public_key, signature, transaction):
            #送信者の残高を計算する
            if self.calculate_total_amount(sender_blockchain_address) < float(value):
                logger.error({'action':'add_transaction','error':'no_value'})
                return False
            #トランザクションを追加する
            self.transaction_pool.append(transaction)
            #トランザクションを追加する
            return True
        #トランザクションの署名を検証する
         return False
    
    #トランザクションを作成する
    def create_transaction(self, sender_blockchain_address,recipient_blockchain_address,
                           value,sender_public_key=None, signature=None):
        #トランザクションを追加する
        is_transacted =self.add_transaction(
            sender_blockchain_address,recipient_blockchain_address,value
            ,sender_public_key,signature)
        #トランザクションが追加された場合は近隣ノードにトランザクションを送信する
        if is_transacted:
            #近隣ノードにトランザクションを送信する
            for node in self.neighbours:
                #近隣ノードにトランザクションを送信する
                requests.put(
                    f'http://{node}/transactions',
                    #トランザクションを送信する
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

    #トランザクションの署名を検証する
    def verify_transaction_signature(
            self,sender_public_key,signature, transaction):
        #トランザクションのハッシュを計算する
        sha256 = hashlib.sha256()
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()
        signature_bytes = bytes().fromhex(signature)
        Verifying_Key = VerifyingKey.from_string(
            bytes().fromhex(sender_public_key),curve=NIST256p)
        verified_Key = Verifying_Key.verify(signature_bytes, message)
        return verified_Key
    #トランザクションのハッシュを計算する
    def valid_proof(self, transactions, previous_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess_block = utils.sorted_dict_by_key({
            'transactions' : transactions,
            'nonce' : nonce,
            'previous_hash' : previous_hash
        })
        guess_hash = self.hash(guess_block)
        return guess_hash[:difficulty] == '0'*difficulty

    #マイニングの証明を行う
    def proof_of_work(self):
        transactions = self.transaction_pool.copy()
        previous_hash = self.hash(self.chain[-1])
        nonce = 0
        while self.valid_proof(transactions, previous_hash, nonce) is False:
            nonce += 1
        return nonce

    #マイニングを行う
    def mining(self):
        # マイニング報酬のトランザクションを追加
        #if not self.transaction_pool:
        #    return False
        
        self.add_transaction(
                sender_blockchain_address=MINING_SENDER,
                recipient_blockchain_address=self.blockchain_address,
                value=MINING_REWARD)
        nonce = self.proof_of_work()
        previous_hash = self.hash(self.chain[-1])
        self.create_block(nonce,previous_hash)
        logger.info({'action':'mining','status':'success'})

        #近隣ノードにマイニングの証明を送信する
        for node in self.neighbours:
            requests.put(f'http://{node}/consensus')

        return True

    #マイニングを開始する
    def start_mining(self):
        is_acquire = self.mining_semaphone.acquire(blocking=False)
        if is_acquire:
            with contextlib.ExitStack() as stack:
                stack.callback(self.mining_semaphone.release)
                self.mining()
                loop = threading.Timer(MINING_TIMER_SEC, self.start_mining)
                loop.start()
    
    #トランザクションの合計金額を計算する
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

    #ブロックチェーンの有効性を検証する
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

    #競合を解決する
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

#ブロックチェーンのクラスをインスタンス化する
blockchain = BlockChain(blockchain_address=BLOCKCHAIN_ADDRESS, port=BLOCKCHAIN_PORT)
#ブロックチェーンを実行する
blockchain.run()