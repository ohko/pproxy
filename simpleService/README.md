# simpleServices
一个简单的多级代理服务器群管理

```
             Server
client1 ---\        /--- proxy3
client2 ---- proxy1 ---- proxy4
client3 ---- proxy2 ---- proxy5

server管理 proxy1、proxy2
client1 <-> proxy1 <-> proxy3 <-> internet
client2 <-> proxy1 <-> proxy4 <-> internet
client3 <-> proxy2 <-> proxy5 <-> internet
```

# 指令
```shell
# 启动主控服务器
./runServer.sh

# 启动多台客户代理服务器
./runClient.sh
./runClient.sh
./runClient.sh

# 主控服务器指令
k格式：user:password
v格式：http://user:password@host:port
v格式：socks5://user:password@host:port
v格式：request:http://host:port/account/request?k=k

# 添加账号
curl 'http://127.0.0.1:8080/account/add?k=k&v=v'
# 批量添加账号
curl 'http://127.0.0.1:8080/account/adds' -d '{"a:b":"","x:y":"http://a:b@127.0.0.1:9999","m:n":"request:http://127.0.0.1:8080/account/request?k=m:n"}'
# 添加动态反查账号
curl 'http://127.0.0.1:8080/account/add?k=k&v=request:http://xxx.com?k=k'
# 删除账号
curl 'http://127.0.0.1:8080/account/del?k=k'
# 账号列表
curl 'http://127.0.0.1:8080/account/list'
# 账号连接断开
curl 'http://127.0.0.1:8080/account/disconnect?k=k'
# 服务器状态
curl 'http://127.0.0.1:8080/status'

# 客户代理服务器指令
# 客户服务器状态
curl 'http://127.0.0.1:8081/status'
```