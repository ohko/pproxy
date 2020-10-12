openssl genrsa -des3 -passout pass:123 -out root.key 2048
openssl req -passin pass:123 -new -subj "/C=CN/ST=Shanghai/L=Shanghai/O=MyCompany/OU=MyCompany/CN=localhost/emailAddress=ohko@qq.com" -key root.key -out root.csr
openssl x509 -passin pass:123 -req -days 3650 -sha256 -extensions v3_ca -signkey root.key -in root.csr -out root.crt
rm -rf root.csr

openssl genrsa -des3 -passout pass:456 -out ssl.key 2048
openssl rsa -passin pass:456 -in ssl.key -out ssl.key
openssl req -new -subj "/C=CN/ST=Shanghai/L=Shanghai/O=MyCompany/OU=MyCompany/CN=localhost/emailAddress=ohko@qq.com" -key ssl.key -out ssl.csr
openssl x509 -passin pass:123 -req -days 36500 -sha256 -extensions v3_req -CA root.crt -CAkey root.key -CAcreateserial -in ssl.csr -out ssl.crt
rm -rf root.key
rm -rf root.crt
rm -rf ssl.csr
rm -rf root.srl
