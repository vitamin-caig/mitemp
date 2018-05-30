all:

install:
	install -D mitemp-poll.py $(DESTDIR)/usr/local/bin/mitemp-poll.py
	install -D mitemp-poll.service $(DESTDIR)/etc/systemd/system/mitemp-poll.service

enable:
	systemctl enable mitemp-poll

restart:
	systemctl daemon-reload
	systemctl restart mitemp-poll