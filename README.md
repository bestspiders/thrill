# thrill  
**使用该ss时必须有一台国内主机和一台国外主机**     
![illustration](https://github.com/bestspiders/thrill/blob/master/illustration.png?raw=true)
参数讲解
```
{
    "server":"0.0.0.0", 
    "server_port":8888,
    "local_port":1030,
    "password":"xxx",
    "timeout":600,
    "proxy_ip":"xxx",
    "proxy_port": 28909
}
```
server此参数为监听的服务端地址   
本地eg:   
```
"server":"39.33.39.12" 
``` 
服务端eg:   
```
"server":"0.0.0.0"
```
server_port此参数为服务端监听的端口   
local_port为客户端监听的本地端口
passwordw为客户端连接服务端的密码   
timeout连接超时时间  
proxy_ip为你的vps的ip   
proxy_port为你vps端口  

本地config.json   
```
{
    "server":"39.33.39.12", 
    "server_port":8888,
    "local_port":1030,
    "password":"123456",
    "timeout":600,
    "proxy_ip":"55.12.52.12",
    "proxy_port": 28909
}
``` 
中继服务器config.json   
```
{
    "server":"0.0.0.0", 
    "server_port":8888,
    "local_port":1030,
    "password":"123456",
    "timeout":600,
    "proxy_ip":"55.12.52.12",
    "proxy_port": 28909
}
```
vps config.json   
```
{
    "server":"0.0.0.0", 
    "server_port":8888,
    "local_port":1030,
    "password":"123456",
    "timeout":600,
    "proxy_ip":"55.12.52.12",
    "proxy_port": 28909
}
```
##客户端启动  
`python local.py`  
##中继端启动
`python relay_server.py`
##国外vps启动
`python server.py`