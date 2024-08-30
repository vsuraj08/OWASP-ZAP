# OWASP-ZAP

1)in terminal run
docker pull zaproxy/zap-stable

2)in terminal run
docker run -u zap -p 8080:8080 -i zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.key=abc123abc


in another terminal run 

python main.py api_endpoints.yaml
