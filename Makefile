all:

install-mitemp-poll:
	install -D mitemp-poll.py $(DESTDIR)/usr/local/bin/mitemp-poll.py
	install -D mitemp-poll.service $(DESTDIR)/etc/systemd/system/mitemp-poll.service

restart-mitemp-poll:
	systemctl daemon-reload
	systemctl enable mitemp-poll
	systemctl restart mitemp-poll

install-zabbix:
	install -D zabbix/mitemp.conf $(DESTDIR)/etc/zabbix/zabbix_agentd.conf.d/mitemp.conf
	./zabbix-config.py
# > $(DESTDIR)/etc/zabbix/zabbix_agentd.conf.d/mitemp_devices.conf
