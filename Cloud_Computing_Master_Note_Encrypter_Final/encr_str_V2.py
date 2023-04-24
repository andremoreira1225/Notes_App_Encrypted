#Se já tiveres, fazer pip3 unistall Crypto, pip3 unistall pycrypto
#De seguida fazer pip3 install pycryptodome
#Module documentation: https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
#https://pycryptodome.readthedocs.io/en/latest/src/cipher/cipher.html
#from typing import final
from Crypto.PublicKey import RSA as RSA_KEYS
import rsa as RSA_MESSAGES

class encr_str:

    def __init__(self):
        self.pubk = ""
        self.pivk = ""
 
    #A exportação das chaves é feita com decode, ou seja, a chave não está entre " b' ******' "
    def generatee_keys(self):
        pair = RSA_KEYS.generate(2048)
        return pair.publickey().export_key('PEM').decode(), pair.export_key('PEM').decode()

    #Aqui o import tinha de ser diferente, porque se fizesse o import da mesma maneira como fazia na chave privada
    #a chave publica tinha que começar "BEGIN RSA PUBLIC KEY", e ela só começa por "BEGIN PUBLIC KEY"
    def import_str_publick(self, key_str):
        self.pubk = RSA_KEYS.import_key(key_str.encode('utf-8'))
         

    def import_str_privatek(self, key_str):
        self.pivk = RSA_MESSAGES.PrivateKey._load_pkcs1_pem(key_str.encode('utf-8'))

    def automated_process_encr(self, text):
            return RSA_MESSAGES.encrypt(text.encode('utf-8'), self.pubk) 

    def automated_process_decr(self, text):
            print(str(text))
            final1: bytes = text.encode('latin1').decode('unicode_escape').encode('latin1')
            return RSA_MESSAGES.decrypt(final1, self.pivk).decode()

    def mannual_decoding(self, msg):
        #[(b'***conteudo unicode****',)]
        #retirar no fim
        moddedMsg = msg[:len(msg)-4]
        #retirar no inicio
        moddedMsg = moddedMsg[4:]
        return moddedMsg
