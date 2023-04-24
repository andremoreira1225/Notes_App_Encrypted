import hashlib
from hmac import compare_digest

class hashcode:
    # função para cifrar a password do utilizador que registou
    def registar(self, email, password):
        stringParaHashR = (str(email) + str(password)).encode('utf-8')
        hash = hashlib.sha512(stringParaHashR)
        hashText = hash.hexdigest()
        return hashText
    # fim da função para cifrar a password do utilizador que registou

    # função que recebe os dados do login para cifrar e comprar com a cifra da password de registo
    def login(self, email, passwordRegister, passwordLogin):
        stringParaHashL = (str(email) + str(passwordLogin)).encode('utf-8')
        hash = hashlib.sha512(stringParaHashL)
        hashTextLogin = hash.hexdigest()
        return self.compare(passwordRegister, hashTextLogin)
    # fim da função que recebe os dados do login para cifrar e comprar com a cifra da password de registo

    # função que vai comprar os dois hash e retornar se fazem match
    def compare(self, passwordRegister, hashTextLogin):
        return compare_digest(passwordRegister, hashTextLogin)
    # fim da função que vai comprar os dois hash e retornar se fazem match




