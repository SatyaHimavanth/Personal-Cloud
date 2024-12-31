To run this program, you must have Python (version 3 or above preferred) installed and configured in your system.

Steps to run the project:

Step 1: After installing and adding Env variables of python, pip install required libraries by using the below command 
```bash
   pip install -r requirements.txt
```
(or)
```bash
   pip3 install -r requirements.txt
```

Step 2: git clone the repository using the below command (make sure you have git installed)
```bash
   git clone https://github.com/SatyaHimavanth/Personal-Cloud.git
   cd Personal-Cloud
```
(or)
download the project from GitHub repo -> code -> Download ZIP and extract it.

Step 3: Create a .env file with an admin email and password (this can only be used to manage users)
```bash
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=securepassword123
```

Step 4: run the project using the below code 
```bash
   python app.py
```
(or)
```bash
   python3 app.py
```

In Project steps to create and access accounts
Step 1: Creation of an account
Click "Register" and enter the required details.

Step 2: Accept the registration request
From the login page log in using the credentials given in .env file
Accept the respective request

Step 3: Login to account
Now log in using the credentials submitted during the registration process

Just so you know, please don't share admin credentials with others.
