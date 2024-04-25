import random
import psycopg2 as p
from hashlib import sha256
from flask import Flask, render_template, request, redirect
from db_details import database,user,password,host,port

from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding
iv = b'JQ\xef\x9dI\x10\xfbn\x96\x86\xfb\x90\x9c\\\xed\xe8'

import pyotp


# print(sha256("xyz".encode('utf-8')).hexdigest())

app = Flask(__name__)

conn = p.connect(database=database,user=user,password=password,host=host,port=port)
curr = conn.cursor()

def t():
  return random.choice(list("0123456789"))

def gen_id():
  return t() + t() + t() + t() + t() + t()

def encrypt_note(key, note):
  global iv
  key = str(key)*3
  k = ""
  for i in key[:-2]:
    k += chr(ord(i) ^ ord('A'))
  key = k.encode('utf-8')
  note = note.encode('utf-8')
  cipher = AES.new(key, AES.MODE_CBC, iv)
  padded_data = Padding.pad(note, AES.block_size)
  ct = cipher.encrypt(padded_data)
  ct_str = b64encode(ct).decode('utf-8')
  return ct_str

def decrypt_note(key, note):
  global iv
  key = str(key)*3
  k = ""
  for i in key[:-2]:
    k += chr(ord(i) ^ ord('A'))
  key = k.encode('utf-8')
  note = note.encode('utf-8')
  ct = b64decode(note)
  cipher = AES.new(key, AES.MODE_CBC, iv)
  decrypted_data = cipher.decrypt(ct)
  pt = Padding.unpad(decrypted_data, AES.block_size)
  pt_str = pt.decode('utf-8')
  return pt_str

def authenticate(id, password):
  p=f"select password from authentication where note_id=\'{id}\';"
  curr.execute(p)
  t = curr.fetchall()
  if t == []:
    return False
  actp = t[0][0]
  return actp==sha256(password.encode('utf-8')).hexdigest()

def get_note(id):
   curr.execute(f"SELECT note_content FROM note WHERE note_id=\'{id}\';")
   return curr.fetchall()[0][0]

def generate_totp():
  key = pyotp.random_base32()
  totp = pyotp.TOTP(key)
  return totp.now(), key

def if_need_totp(note_id):
  curr.execute(f"SELECT totp FROM authentication WHERE note_id=\'{note_id}\';")
  t = curr.fetchall()
  if t == []:
    return False
  elif t[0][0] == None:
    return False
  return True

def confirm_TOTP(note_id,totp_input):
  curr.execute(f"SELECT totp FROM authentication WHERE note_id=\'{note_id}\';")
  key = curr.fetchall()[0][0]
  totp = pyotp.TOTP(key)
  if totp.verify(totp_input):
    return True
  return False

# Routes


@app.route('/edit/<int:note_id>',methods=['POST'])
def edit(note_id):
  note = encrypt_note(note_id,request.form['note'])
  if note.strip()=="":
    note = " "
  curr.execute(f"UPDATE note SET note_content=\'{note}\' WHERE note_id=\'{note_id}\';")
  conn.commit()
  return redirect("/",code=302)

@app.route('/')
def Home():
  return render_template("home.html")

@app.route('/newnote',methods=['GET', 'POST'])
def create_note():
  if request.method == 'POST':
    note_id = gen_id()
    curr.execute("select note_id from note;")
    note_ids = [i[0] for i in curr.fetchall()]
    while note_id in note_ids:
      note_id = gen_id()
    return render_template("newnote.html",note_id=note_id)
  else:
    note_id = gen_id()
    curr.execute("select note_id from note;")
    note_ids = [i[0] for i in curr.fetchall()]
    while note_id in note_ids:
      note_id = gen_id()
    return render_template("newnote.html",note_id=note_id)
  

@app.route('/created',methods=['POST'])
def created_note():
  note_id = request.form['note_id']
  note = encrypt_note(note_id," ")
  pwd = request.form['pwd']
  epwd = sha256(pwd.encode('utf-8')).hexdigest()
  curr.execute(f"insert into authentication values(\'{note_id}\',\'{epwd}\');")
  conn.commit()
  curr.execute(f"insert into note values(\'{note_id}\',\'{note}\');")
  conn.commit()
  return redirect("/",code=302)

@app.route('/gotonote',methods=['POST'])
def goto():
  return redirect(f"/note/{request.form['note_id']}",code=302)

@app.route("/note/<int:note_id>")
def show_note(note_id):
  need_totp=if_need_totp(note_id)
  return render_template("note.html", note_id=str(note_id),totp=need_totp)

@app.route("/note",methods=['POST', 'GET'])
def note_check():
  pwd = request.form["pwd"]
  nid = request.form["note_id"]
  if authenticate(nid,pwd):
    note = decrypt_note(nid,get_note(nid))
    return render_template("index.html",note=note,nid=nid)
  else:
    return redirect(f"/note/{nid}",code=302)

@app.route("/<int:note_id>/totp", methods=['POST'])
def create_TOTP(note_id):
  totp, key = generate_totp()
  return render_template("totp.html",key=key,note_id=note_id)

@app.route("/verify_TOTP", methods=['POST'])
def verify_TOTP():
  key = request.form["key"]
  note_id = request.form["note_id"]
  totp_input = request.form["totp"]
  totp = pyotp.TOTP(key)
  
  if totp.verify(totp_input):
    curr.execute(f"update authentication set totp=\'{key}\' where note_id=\'{note_id}\'")
    conn.commit()
    return redirect(f"/note/{note_id}",code=302)
  else:
    return render_template("totp.html",key=key,note_id=note_id)

@app.route("/notetotp", methods=['POST', 'GET'])
def notetotp():
  note_id = request.form["note_id"]
  pwd = request.form["note_pwd"]
  totp = request.form["note_totp"]
  if authenticate(note_id,pwd) and confirm_TOTP(note_id,totp):
    note = decrypt_note(note_id,get_note(note_id))
    return render_template("index.html",nid=note_id,note=note)
  else:
    return redirect(f"/note/{note_id}",code=302)

if __name__ == '__main__':
    app.run(debug=True)