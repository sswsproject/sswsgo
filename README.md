# sswsgo

Like ssws, sswsgo is a re-work of shadowsocks-heroku(https://github.com/mrluanma/shadowsocks-heroku), written in Go instead of nodejs or python.

Other things, sswsgo is just like ssws, only not in some usage differences.

sswsgo combines remote server and local socks5 server(or client to remote) in one program. please follow the usage instruction to use it.

Usage

On your remote server, adjust 'PORT' part in the source code and then compile it. You need set a 'SSWSGOPASS' enviroment varible as your passcode, then use 'sswsgo -s -sport 80' to start the server.

On the client side, start the local socks5 server with following command(example):

sswsgo -c -key 1234567890123456 -proxy 10.10.10.10:3228 -hostname 0.0.0.0 -port 7071 -urlstr any.valid.domain -sport 80

again, you must not use '1234567890123456' as the passcode, you should replace it with your own passcode, same as the one set up on your server enviroment variable. The '-port' part indicate the socks5 server port you will use. The '-urlstr' part is the remote server which deployed sswsgo, replace the domain name with your own, '-sport 80' indicates the same port you use on your server. The '-proxy' part is optional, if you work in an enviroment with an HTTP proxy, you need use this one, otherwise, you can just omit this part in the command.

Last step, open your favorite browser, set the socks5 proxy to your local ip address and the port number you set with the '-port' parameter in the client starting command. It's done.

