# Attack Demo

### Run:
`$ python demo.py`

To get the menu:
![alt menu](https://i.imgur.com/GApZuRM.png)


### Or see options: 
```
optional arguments:
  -h, --help            show this help message and exit
  
  -p PROFILE, --profile PROFILE      Attackers AWS profile name (as appears in ~/.aws/credentials)
  -r REGION, --region REGION         The region in deployed the DVSA on (default is `us-east-1`)
  -e ENDPOINT, --endpoint ENDPOINT   The endpoint (API Gateway) for the lambda with XXE Vulnerability
  -a ACCOUNT, --account ACCOUNT      The AWS Account ID on which DVSA is installed
  -x PROXY, --proxy PROXY            [HOST]:[PORT]
  -v, --verbose                      Print additional information to stdout
  -d ATTACK, --attack ATTACK         Run attack directly. Use: [xxe, injection]
```

- Examples:

`$ python demo.py --endpoint https://9gpdohmi21.execute-api.us-east-1.amazonaws.com/dev/xml`

`$ python demo.py --endpoint https://9gpdohmi21.execute-api.us-east-1.amazonaws.com/dev/xml --attack xxe`

`$ python demo.py --attack injection --account 161635420639`

