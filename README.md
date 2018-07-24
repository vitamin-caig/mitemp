Simple integration of Xiaomi MiJia Temperature Humidity Sensor (model LYWSDCGQ / 01ZM).

Typical workflow:

- background service mitemp-poll scans for available Mijia devices and dumps basic sensors to /tmp/mijia/${mac} file in Name=value format
- zabbix config specifies names for particular devices and addresses:
/etc/zabbix/mitemp.conf
'''
{
  "data":
  [
    {"{#SENSORNAME}":"Room1", "{#SENSORADDRESS}":"4C:65:A8:XX:YY:ZZ"},
    ...
  ]
 }
 /etc/zabbix/zabbix_agentd.conf.d/mitemp.conf:
 
