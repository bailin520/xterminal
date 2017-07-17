# xTerminal([中文](https://github.com/zhaojh329/xterminal/blob/master/README_ZH.md))([github](https://github.com/zhaojh329/xterminal))

![](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic "License")

XTerminal is a remote web shell tool for multi terminal devices. With it, you can access the Shell in any of your devices that can access the Internet via the 
browser on any device that can access the Internet. XTerminal is based on [evmongoose](https://github.com/zhaojh329/evmongoose) implementation, It consists of 
two parts, server and client.

![](https://github.com/zhaojh329/image/blob/master/xterminal.png)

# [Online experience](https://jianhuizhao.f3322.net:8443)
	username: xterminal
	password: xterminal
	macaddr: 66:09:80:01:22:15
	
# Features
* Based on Web, easy to use
* Support for connecting multiple terminals at the same time
* Support uploading files to terminal devices
	
# How To Install
## Install server on Ubuntu
### Install dependency
* [evmongoose](https://github.com/zhaojh329/evmongoose/blob/master/README.md)

* mosquitto

		sudo apt install mosquitto

### Install xTerminal Server
    git clone https://github.com/zhaojh329/xterminal.git
	cd xterminal
	git co c
	cmake . && sudo make install
    cd ubuntu
	sudo make install

### Run Server on Ubuntu
	sudo /etc/init.d/xterminal start

## Install Client on OpenWRT/LEDE
### Download/Compile
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
	
	# to upload file to device, must be select ssl
	Libraries  --->
		Networking  --->
			*- evmongoose
				Configuration  --->
					Selected SSL library (OpenSSL)  --->
	
	make package/xterminal/compile V=s

### Modify config(/etc/config/xterminal)
	config base
        option  mqtt_hostname   'jianhuizhao.f3322.net'
        option  mqtt_port       '8883'
		
# How to use
# Query online device
	https://server:8443/list

# Connect to devic
In the browser, enter the server address(https://server:8443), the default port number 8443, and then in the page appears to enter the the 
MAC address of then device to be connected to, MAC address format can be:
xx:xx:xx:xx:xx:xx, xx-xx-xx-xx-xx-xx, xxxxxxxxxxxxx

# Disonnect to devic
Execute the exit command in the shell environment

# How To Contribute
Feel free to create issues or pull-requests if you have any problems.

**Please read [contributing.md](https://github.com/zhaojh329/xterminal/blob/master/contributing.md)
before pushing any changes.**

# Thanks for the following project
* [evmongoose](https://github.com/zhaojh329/evmongoose)
* [xterm.js](https://github.com/sourcelair/xterm.js)

# If the project is helpful to you, please do not hesitate to star. Thank you!
