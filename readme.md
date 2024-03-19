Install
1. Ensure that python is installed
2. Make sure to cd to this directory (authlr2)
3. "pip install -r requirements.txt"

Running the script
1. Ensure you cd to this directory (authlr2)
2. Ensure your execution policy allows scripts
   1. "Set-ExecutionPolicy -Scope Process Unrestricted" (in admin prompt)
3. "run.ps1"
4. You should see 4 powershell windows open, with each flask application

Example Usage
1. Using the python console
   1. import requests #imports the requests lib
   2. cred = {'username': 'alice', 'password': 'password1'} #creates a dict with a user
   3. requests.post('http://127.0.0.1:10001/login', data=cred).text #sends the creds to the client application
2. Watch the response and look at the powershell windows