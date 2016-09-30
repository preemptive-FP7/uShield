build:


clean:


install:
	install -m 755 -o root -g root cef_forwarder /usr/local/bin/
	install -m 755 -o root -g root cef_forwarder_startup /etc/init.d/cef-forwarder

uninstall:
	rm /usr/local/bin/cef_forwarder
	rm /etc/init.d/cef-forwarder

.PHONY: build clean install uninstall
