#import email
#from pickle import TRUE
#from statistics import multimode
#from traceback import print_tb
from flask import Flask, request, render_template, redirect, url_for, session
import mysql.connector 
from mysql.connector import Error
#from mysqlx import Row
#from sqlalchemy import null
import mainPasswordHash 
import encr_str_V2 as encr_notes

#Criação de uma instância do objeto Flask
app = Flask(__name__)
#Secret key criada para podermos usar as variáveis de sessão, é obrigatório
app.secret_key = "notes"
#Criação de uma instância do objeto encr_str (Para gerar chaves, encriptar e desincriptar mensagens)
masterEncrypt = encr_notes.encr_str()
hashcode = mainPasswordHash.hashcode()
#conecção a base de dados
try:
    notesDb = mysql.connector.connect(host="34.65.0.99", 
                                        database="cnnotes", 
                                        #autÊnticação instância da BD na cloud
                                        user="root", 
                                        passwd="Admin123456")

    #Caso a conexão seja sucedida
    #Aqui retiramos a informação que vem da base de dados. 
    if notesDb.is_connected():
        db_Info = notesDb.get_server_info()
        print("Connected to MySQL Server version ", db_Info)
        cursorDb = notesDb.cursor()
        cursorDb.execute("select database();")
        record = cursorDb.fetchone()
        print("Estamos conectados a database: ", record)
#Caso alguma coisa dentro do try dê erro, fazer print de erros.
#Caso contrário, informar user que a conexão foi sucedida. 
except Error as e:
    print("Erros ocurram na conecção com a database ", e)
finally: 
        if notesDb.is_connected():
            print("A conexão foi aberta!")
#fim da conecção

# função para login
@app.route("/", methods = ["GET", "POST"])
def loginPage():
    #Inicialização da variável de sessão
    session["id_user"] = 0
    if request.method == "POST":
        #Retiramos a informação dos input text do html
        pEmail = request.form['email']
        pPassword = request.form['password']
        #Vamos buscar informações á base de dados se o e-mail existir na mesma
        verify = ("SELECT user_id, email, password FROM usersclients WHERE email=%s")
        cursorDb.execute(verify, (pEmail,))
        row = cursorDb.fetchone()
        #Usamos 2 métodos da classe hash code que criamos
        #aplicamos o SHA-512 á junção do e-mail e password
        #Caso alfanumerico produzido com os dados inseridos, for igual ao alfanumerico que está na bd, então concedemos ligação
        firstH = hashcode.registar(pEmail, pPassword)
        isEqual = hashcode.compare(row[2], firstH)
        #Caso seja verdade, vamos guardar na variável de sessão o id do utilzador, e fazemos um redirect á página "/keys/"
        #Caso contrário, o utilizador volta á página de login
        if isEqual == True:
            session["id_user"] = row[0]
            return redirect("/keys/")
        elif pEmail == None or pPassword == None:
            return redirect(url_for('loginPage'))
        else:
            return redirect(url_for('loginPage'))
    return render_template("login.html")
# fim da função para login

# função para registar o utilizador
@app.route("/register/", methods = ["GET", "POST"])
def registerUser():
    if request.method == "POST":
        #Retiramos a informação dos input text do html
        pUser = request.form['username']
        pEmail = request.form['email']
        pPassword = request.form['password'] 
        #Criamos um alfanumérico, aplicando o SHA-512 á junção do e-mail+password 
        hashPass = hashcode.registar(pEmail, pPassword)  
        #Inserimos na base de dados o novo utilizador
        # #Rederecionamos o user para página "requestkeys" 
        cursorDb.execute("INSERT INTO usersclients (username, email, password) VALUES (%s, %s, %s)" , (pUser, pEmail, hashPass))
        notesDb.commit()
        return redirect(url_for('requestKeys'))
    return render_template("register.html")
# fim da função para registar o utilizador

# função para gerar as chaves para o utilizador
@app.route("/keysRequest/", methods = ["GET", "POST"])
def requestKeys():
    #Usamos a função da classe masterEncrypt que criamos para gerar a chave pública e privada do utilizador.
    #Enviamos para o HTML estas chaves para o utilizador guardar. 
    chavePub, chavePriv = masterEncrypt.generatee_keys()
    return render_template("requestKeys.html", chavePub=chavePub, chavePriv=chavePriv)
# fim da função para gerar as chaves para o utilizador

# função para o utilizador fornecer as chaves para encriptação
@app.route("/keys/", methods = ["GET", "POST"])
def keysPage(): 
    if request.method == "POST":
    #Retiramos a informação dos input text do html 
    #Fazemos o import para a função da classe masterEncrypt que criamos, para ficarem guardadas nos atributos desta classe
       pCpub = request.form['chavePublica']
       masterEncrypt.import_str_publick(pCpub)
       pCpiv = request.form['chavePrivada']
       masterEncrypt.import_str_privatek(pCpiv)
       return redirect(url_for("inicialPage"))
    else:
        return render_template("keysRequest.html")
# fim da função para o utilizador fornecer as chaves para encriptação

# função para o mostrar o listar as notas do utilizador
@app.route("/index/", methods = ["GET"])
def inicialPage():
    #Guardamos o conteúdo da variável de sessão nesta variável local "user_id"
    if "id_user" in session:
        user_id = session['id_user']
    #Vamos buscar á bd as notas e titulo das mesmas do utilizador
    #Enviamos para o HTML 
    query = "SELECT * FROM notesclients WHERE user_id_ref_note=%s"
    cursorDb.execute(query, (user_id,))
    row = cursorDb.fetchall()
    return render_template("listPersonalNotes.html", todo_list=row)
# fim da função para o mostrar o listar as notas do utilizador

# função para o mostrar o adicionar uma nova nota 
@app.route("/note/add", methods = ["POST"])
def add():
    #Guardamos o conteúdo da variável de sessão nesta variável local "user_id"
    if "id_user" in session:
        user_id = session['id_user']
    #Retiramos a informação do input text do html 
    title = request.form['tituloNota']
    #encriptamos esta nova nota com ""
    noteEncr = masterEncrypt.automated_process_encr("")
    #inserimos na BD nova nota + texto encriptado
    query = "INSERT INTO notesclients (user_id_ref_note, title, note) VALUES (%s, %s, %s)" 
    cursorDb.execute(query, (user_id,title,noteEncr))
    notesDb.commit()
    return redirect(url_for('inicialPage'))
# fim da função para o mostrar o adicionar uma nova nota 

# função para eliminar uma nota que o utilizador queira
# Passamos o parâmetro do todo_id pelo URL, para usar dentro da função
@app.route("/note/<int:todo_id>/delete/")
def delete(todo_id):
    #Guardamos o conteúdo da variável de sessão nesta variável local "user_id" 
    if "id_user" in session:
        user_id = session['id_user']
    #Excluimos da BD a nota pretendida
    query = "DELETE FROM notesclients WHERE user_id_ref_note=%s AND note_id=%s"
    cursorDb.execute(query, (user_id,todo_id))
    notesDb.commit()
    return redirect(url_for('inicialPage'))    
# fim da função para eliminar uma nota que o utilizador queira

# função para ver uma nota que o utilizador queira
@app.route("/note/<int:todo_id>/view/", methods=['POST', 'GET'])
def viewPage(todo_id):
    #Guardamos o conteúdo da variável de sessão nesta variável local "user_id"
    if "id_user" in session:
        user_id = session['id_user']
    #Vamos buscar á BD todas as notas e titulos das mesmas do utilizador
    query = "SELECT * FROM notesclients WHERE user_id_ref_note=%s AND note_id=%s"
    cursorDb.execute(query, (user_id, todo_id))
    row = cursorDb.fetchall()
    #Vamos buscar de maneira separada a nota á bd
    #É feito desta maneira, pois se fossemos buscar a nota da query de cima, o unicode vinha cortado
    #Desta maneira, vinha o unicode na totalidade
    queryNote = "SELECT note FROM notesclients WHERE user_id_ref_note=%s AND note_id=%s"
    cursorDb.execute(queryNote, (user_id, todo_id))
    rowNote = cursorDb.fetchall()
    #Guardamos todo o conteudo proveniente da BD como string
    strSOriginal = str(row)
    note = str(rowNote)
    #Mostrar na apresentação o conteúdo encriptado que vem da BD
    print("Saida da nota na db ", note)
    #Fazemos as devidas formatações para conseguirmos tirar os valores que queremos do bruto que vem da BD
    testeIDS = strSOriginal.split(",")
    title = testeIDS[2].replace(" ", "").replace("'", "").replace("[", "").replace("(", "").replace("]", "").replace(")", "")
    #No caso da nota, criamos uma função própria que tira o excesso da string
    #[(b'***conteudo unicode****',)]
    #depois de formatar o texto encriptado, enviamos para a função de desincriptação, para desencriptar a mensagem 
    note = masterEncrypt.mannual_decoding(note)
    noteDecr = masterEncrypt.automated_process_decr(note)
    return render_template("viewNote.html", Id=todo_id, title=title, note=noteDecr)
# fim da função para ver uma nota que o utilizador queira

# função para editar uma nota que o utilizador queira
@app.route("/note/<int:todo_id>/edit/", methods=["POST", "GET"])
def editPage(todo_id):
    #Processo igual á função this.viewPage()
    if "id_user" in session:
        user_id = session['id_user']
    query = "SELECT * FROM notesclients WHERE user_id_ref_note=%s AND note_id=%s"
    cursorDb.execute(query, (user_id, todo_id))
    row = cursorDb.fetchall()
    queryNote = "SELECT note FROM notesclients WHERE user_id_ref_note=%s AND note_id=%s"
    cursorDb.execute(queryNote, (user_id, todo_id))
    rowNote = cursorDb.fetchall()
    strSOriginal = str(row)
    note = str(rowNote)
    testeIDS = strSOriginal.split(",")
    title = testeIDS[2].replace(" ", "").replace("'", "").replace("[", "").replace("(", "").replace("]", "").replace(")", "")
    noteDecr = masterEncrypt.mannual_decoding(note)
    noteDecr = masterEncrypt.automated_process_decr(noteDecr)
    #Aqui vamos guardar as alterações
    if request.method == "POST":
        #Retiramos a informação do input text do html 
        updateNote = request.form['noteEdit']
        updateNote = str(updateNote)
        #Encriptamos a nova mensagem
        noteEncr = masterEncrypt.automated_process_encr(updateNote)
        #Fazemos update na base de dados
        query = "UPDATE notesclients SET note=%s WHERE user_id_ref_note=%s AND note_id=%s"
        cursorDb.execute(query, (noteEncr, user_id, todo_id,))
        notesDb.commit()
        return redirect(url_for('inicialPage'))
    else:
        return render_template("editNote.html", Id=todo_id, title=title, note=noteDecr)
# fim da função para editar uma nota que o utilizador queira


#iniciar a app caso ela seja iniciada através deste ficheiro
if __name__ == "__main__":
    app.run(debug=True)