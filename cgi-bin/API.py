#pip install rsa
#pip install gostcrypto
import cgi
import sqlite3
import random, string
import html, hashlib
import datetime, time
import rsa, gostcrypto

form = cgi.FieldStorage() #получаем данные из форм
send = form.getfirst("send") #кнопки
open = form.getfirst("open")
registration = form.getfirst("registration")
db = sqlite3.connect("Users.db") #подключаемся к базе данных

def Show_in_browser(text):
    print ("Content-type:text/html")
    print()
    print(text)

def Add_Message (key, recipient, sender, message, time):
    value = key, recipient, sender, message, time
    db.cursor().execute("INSERT INTO secrets (key, recipient, sender, message, time) VALUES (?, ?, ?, ?, ?)", (value))
    db.commit()

def Add_User(login, password, salt, time, public_key, private_key):
    value = login, password, salt, time, public_key, private_key
    db.cursor().execute("INSERT INTO users (login, password, salt, time, public, private) VALUES (?, ?, ?, ?, ?, ?)", (value)) #кортеж от SQL-инъекций
    db.commit() #сохраняем базу

def Check_db(select, fromm, where, value):
    db = sqlite3.connect("Users.db")
    db.row_factory = lambda cursor, row: row[0]
    db_req = f'SELECT {select} FROM {fromm} WHERE {where} == "{value}";' #ищем есть ли в базе
    db_value = db.cursor().execute(db_req).fetchone() #записываем в переменную
    return db_value

def Delete_db(fromm, where, value):
    db = sqlite3.connect("Users.db")
    db.row_factory = lambda cursor, row: row[0]
    #db_req = f"DELETE FROM secrets WHERE key == '{value}';"
    db_req = f"DELETE FROM {fromm} WHERE {where} == '{value}';"
    db_value = db.cursor().execute(db_req)
    db.commit()


def Send():
    login_sender = html.escape(form.getfirst("login_sender")) # html.escape - экранируем от XXS-атак через форму ввода
    password_sender = html.escape(form.getfirst("password_sender")).encode('utf-8')
    login_recipient = html.escape(form.getfirst("login_recipient"))
    secret = html.escape(form.getfirst("secret")).encode('utf-8')

    if Check_db('login', 'users', 'login', login_sender) != None:  #Проверям есть ли отправитель в базе
        time_del_login_s_str = Check_db('time', 'users', 'login', login_sender) #получаем время хранения учкетной записи
        time_del_login_s = datetime.datetime.strptime(time_del_login_s_str, '%Y-%m-%d %H:%M:%S.%f')
        if datetime.datetime.now() < time_del_login_s: #не истекло ли время действия учетной записи отправителя
            salt = Check_db('salt', 'users', 'login', login_sender)
            hash_password_sender = hashlib.sha256(password_sender + salt).hexdigest()
            if Check_db('password', 'users', 'login', login_sender) == hash_password_sender: #сравниваем логин и пароль
                if Check_db('login', 'users', 'login', login_recipient) == login_recipient: #есть ли получатель в базе
                    time_del_login_r_str = Check_db('time', 'users', 'login', login_recipient)
                    time_del_login_r = datetime.datetime.strptime(time_del_login_r_str, '%Y-%m-%d %H:%M:%S.%f')
                    if datetime.datetime.now() < time_del_login_r: #не истекло ли время действия учетной записи получателя
                        time_rec = datetime.datetime.now() #расчитали время сейчас
                        time_del = time_rec+datetime.timedelta(days = 7) #расчитываем время удаления сообщения
                        k = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(16)]) #идентификатор
                        if Check_db('key', 'secrets', 'key', k) != None: # на случай, если сгенерированный ключ уже есть в базе
                            while Check_db('key', 'secrets', 'key', k) != None:
                                k = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(16)])
                                Check_db('key', 'secrets', 'key', k)

                        if Check_db('key', 'secrets', 'key', k) == None:
                            ks = Check_db('public', 'users', 'login', login_recipient)
                            key = rsa.PublicKey.load_pkcs1(ks)
                            encrypted_secret = rsa.encrypt(secret, key) #шифруем сообщение

                            Add_Message(k, login_recipient, login_sender, encrypted_secret, time_del)
                            Show_in_browser(f"Для пользователя {login_recipient} сформерован идентификатор: {k}\n")
                            print(''' <html lang = "ru"> <body> <br>
                                Отправьте ключ получателю секретного сообщения.<br>
                                Чтобы получить доступ к секретному сообщению, получателю необходимо ввести этот ключ в соответсвующее поле.
                                </body>
                            </html>''')
                    else:
                        Show_in_browser("Истек срок дейсствия учетной записи получателя")
                        Delete_db('users', 'login', login_recipient)
                else: Show_in_browser("Получатель с таким логином не зарегистрирован или время действия его учетной записи истекло")
            else: Show_in_browser("Неверный пароль")
        else:
            Show_in_browser("Время действия вашей учетной записи истекло")
            Delete_db('users', 'login', login_sender)
    else: Show_in_browser("Вы не зарегистрированы в системе или время действия вашей учетной записи истеко")


def Open():
    login = form.getfirst("login") #поля для получения
    pas = form.getfirst("password")
    password = pas.encode('utf-8')
    key = form.getfirst("key")

    if Check_db('login', 'users', 'login', login) != None: #есть ли получатель в базе
        time_del_login_str = Check_db('time', 'users', 'login', login) #получаем время хранения учетной записи
        time_del_login = datetime.datetime.strptime(time_del_login_str, '%Y-%m-%d %H:%M:%S.%f') #преобразуем строку в формат даты и времени
        if datetime.datetime.now() < time_del_login: #проверям время действия учетной записи
            salt = Check_db('salt', 'users', 'login', login)
            hash_password = hashlib.sha256(password + salt).hexdigest()
            if Check_db('password', 'users', 'login', login) == hash_password: #проверям пароль
                if Check_db('recipient', 'secrets', 'key', key) == login: #ищем соответсвие логина и идентификатора сообщения
                    time_del_message_str = Check_db('time', 'secrets', 'key', key)
                    time_del_message = datetime.datetime.strptime(time_del_message_str, '%Y-%m-%d %H:%M:%S.%f')
                    if datetime.datetime.now() < time_del_message: #проверям не истекло ли время хранения сообщения
                        sender = Check_db('sender', 'secrets', 'key', key)
                        message_encrypt = Check_db('message', 'secrets', 'key', key)

                        key_kuznechik = pas.rjust(32, '0').encode('utf-8')
                        key_RSA_encript = Check_db('private', 'users', 'login', login)
                        obj = gostcrypto.gostcipher.new('kuznechik', key_kuznechik, gostcrypto.gostcipher.MODE_ECB, pad_mode=gostcrypto.gostcipher.PAD_MODE_1)

                        key_RSA = obj.decrypt(key_RSA_encript).decode('utf-8')
                        key_rsa_import = rsa.PrivateKey.load_pkcs1(key_RSA)
                        message = rsa.decrypt(message_encrypt, key_rsa_import).decode('utf-8')
                        Show_in_browser(f"Пользователь {sender} отправил Вам сообщение: {message}")
                        Delete_db('secrets', 'key', key)
                    else:
                        Show_in_browser("Истек срок хранения сообщения")
                        Delete_db('secrets', 'key', key)
                else: Show_in_browser("Ключ недействителен или сообщение предназначено другому пользователю")
            else: Show_in_browser("Непрвильный пароль")
        else:
            Show_in_browser("Время действия вашей учетной записи истекло")
            Delete_db('users', 'login', login)
            Delete_db('secrets', 'recipient', login)
    else: Show_in_browser("Вы не зарегистрированы в системе или время действия вашей учетной записи истеко")


def Registration():
    login_new = html.escape(form.getfirst("login_new"))
    password = html.escape(form.getfirst("password1"))
    password1 = password.encode('utf-8')
    password2 = html.escape(form.getfirst("password2")).encode('utf-8')

    salt = ''.join([random.choice(string.ascii_lowercase + string.digits) for i in range(64)]).encode('utf-8')
    hash_password1 = hashlib.sha256(password1 + salt).hexdigest()
    hash_password2 = hashlib.sha256(password2 + salt).hexdigest()

    time_rec = datetime.datetime.now() #расчитали время сейчас
    time_del = time_rec+datetime.timedelta(days = 365) #расчитываем время удаления пользователя

    key = password.rjust(32, '0').encode('utf-8') #добавляем к паролю символы до нужной длинный

    if Check_db('login', 'users', 'login', login_new) == None:
        if hash_password1 == hash_password2:
            (public_key, private_key) = rsa.newkeys(2048) #формирование ключей для RSA
            pub_k = public_key.save_pkcs1()
            pr_k = private_key.save_pkcs1()

            obj = gostcrypto.gostcipher.new('kuznechik', key, gostcrypto.gostcipher.MODE_ECB, pad_mode=gostcrypto.gostcipher.PAD_MODE_1)
            encrypted_private_key = obj.encrypt(pr_k) #шифруем приватный ключ кузнечиком

            Add_User(login_new, hash_password1, salt, time_del, pub_k, encrypted_private_key)
            Show_in_browser("Вы зарегестрированы, теперь вы можете отправлять и получать секретные сообщения")
        else: Show_in_browser("Вы не прошли проверку пароля, попробуйте еще раз")
    else: Show_in_browser("Такой логин уже существует, придумайте другой")

if send != None: Send()
elif open != None: Open()
elif registration != None: Registration()
