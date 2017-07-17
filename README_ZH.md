# xTerminal([github](https://github.com/zhaojh329/xterminal))

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

xTerminal是一个多终端的远程Web Shell工具。有了它，你可以在任何一台能上网的设备上通过浏览器访问你的任何一台能上网的设备的Shell。它非常适合公司
对公司部署在全球各地的成千上万的Linux设备进行远程调试。它基于[evmongoose](https://github.com/zhaojh329/evmongoose)实现，由客户端和服务器两部分构成。

![](https://github.com/zhaojh329/image/blob/master/xterminal_zh.png)

# [在线体验](https://jianhuizhao.f3322.net:8443)
	用户名: xterminal
	密码: xterminal
	macaddr: 66:09:80:01:22:15
	
# 特性
* 基于Web，使用简单
* 支持同时连接多个终端
* 支持上传文件到终端设备
	
# 安装
## 在Ubuntu上安装Server
### 安装依赖
* [evmongoose](https://github.com/zhaojh329/evmongoose/blob/master/README_ZH.md)

* mosquitto

		sudo apt install mosquitto
	
### 安装 xTerminal Server
    git clone https://github.com/zhaojh329/xterminal.git
	cd xterminal && git co c
	cmake . && sudo make install
    cd ubuntu
	sudo make install

### 在Ubuntu上运行服务器
	sudo /etc/init.d/xterminal start
	
## 安装客户端 OpenWRT/LEDE
### 下载/编译
	git clone https://github.com/zhaojh329/evmongoose.git
	cp -r evmongoose/openwrt openwrt_dir/package/evmongoose
	
	git clone https://github.com/zhaojh329/xterminal.git
	cd xterminal && git co c
	cp -r openwrt openwrt_dir/package/xterminal-c
	
	cd openwrt_dir
	./scripts/feeds update -a
	./scripts/feeds install -a
	
	make menuconfig
	Utilities  --->
		Terminal  --->
			<*> xterminal-c
	
	# 上传文件到终端设备需要ssl支持
	Libraries  --->
		Networking  --->
			*- evmongoose
				Configuration  --->
					Selected SSL library (OpenSSL)  --->
					
	make package/xterminal/compile V=s

### 修改配置(/etc/config/xterminal)
	config base
        option  mqtt_hostname   'jianhuizhao.f3322.net'
        option  mqtt_port       '8883'
	
# 使用
# 查询在线设备
	https://server:8443/list
	
# 连接设备
在浏览器中输入服务器地址，https协议，默认端口号8443（https://server:8443），然后在出现的页面中输入要连接的设备MAC地址，MAC地址的格式可以是：
xx:xx:xx:xx:xx:xx, xx-xx-xx-xx-xx-xx, xxxxxxxxxxxxx

# 断开连接
在终端Shell环境执行exit命令

# 贡献代码

xTerminal使用github托管其源代码，贡献代码使用github的PR(Pull Request)的流程，十分的强大与便利:

1. [创建 Issue](https://github.com/zhaojh329/xterminal/issues/new) - 对于较大的
	改动(如新功能，大型重构等)最好先开issue讨论一下，较小的improvement(如文档改进，bugfix等)直接发PR即可
2. Fork [xterminal](https://github.com/zhaojh329/xterminal) - 点击右上角**Fork**按钮
3. Clone你自己的fork: ```git clone https://github.com/$userid/xterminal.git```
4. 创建dev分支，在**dev**修改并将修改push到你的fork上
5. 创建从你的fork的**dev**分支到主项目的**dev**分支的[Pull Request] -  
	[在此](https://github.com/zhaojh329/xterminal)点击**Compare & pull request**
6. 等待review, 需要继续改进，或者被Merge!
	
## 感谢以下项目提供帮助
* [evmongoose](https://github.com/zhaojh329/evmongoose)
* [xterm.js](https://github.com/sourcelair/xterm.js)

# 技术交流
QQ群：153530783

# 如果该项目对您有帮助，请随手star，谢谢！
