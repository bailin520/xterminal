all:
	@echo "Please 'sudo make install'"

install:
	rm -rf /etc/xterminal
	install -m0755 xterminal.init /etc/init.d/xterminal
	mkdir /etc/xterminal
	cp -r ../www /etc/xterminal/www
	cp server.pem /etc/xterminal
	cp server.key /etc/xterminal
	
uninstall:
	rm -rf /etc/init.d/xterminal /etc/xterminal
