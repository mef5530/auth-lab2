import requests

resp = requests.post(
    'http://127.0.0.1:10001/login',
    data={
        'username': 'alice',
        'password': 'password1'
    }
)

print('\n----------------------------------------------------------------')
for k, v in resp.json().items():
    print(f'|- {k}: {v}')
print('----------------------------------------------------------------\n')