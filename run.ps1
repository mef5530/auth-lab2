# Define the command to run Flask applications
$pythonExec = "python"
$flaskApp1 = "AuthLab2Project\auth_server.py"
$flaskApp2 = "AuthLab2Project\app_server.py"
$flaskApp3 = "AuthLab2Project\client_application.py"
$flaskApp4 = "AuthLab2Project\oauth_provider.py"

# Start each Flask app in a new PowerShell window
Start-Process PowerShell -ArgumentList "-NoExit", "-Command & { $pythonExec $flaskApp1 }"
Start-Process PowerShell -ArgumentList "-NoExit", "-Command & { $pythonExec $flaskApp2 }"
Start-Process PowerShell -ArgumentList "-NoExit", "-Command & { $pythonExec $flaskApp3 }"
Start-Process PowerShell -ArgumentList "-NoExit", "-Command & { $pythonExec $flaskApp4 }"
