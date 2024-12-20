#!/usr/bin/python3

from argparse import ArgumentParser
import pexpect
import time
from datetime import datetime, timedelta
import logging
import os
import re
import struct
import sys
from subprocess import call
from multiprocessing import Process

class Event(object):
    def __init__(self, mac, key, value):
      self.mac = mac.upper()
      self.key = key
      self.value = value

    def __str__(self):
      return f'{self.mac}: {self.key}={self.value}'

class Controller(object):
    EVENT = re.compile(r'Device (?P<mac>..:..:..:..:..:..) (?P<key>[^:]+): ?(?P<value>.+)?')
    ANNOUNCE = re.compile(r'Device (?P<mac>..:..:..:..:..:..) (?P<alias>.+)')
    ATTR = re.compile(r'/org/bluez/hci\d+/dev_(?P<mac>.._.._.._.._.._..)/(?P<key>\S+) Notification:')
    DUMP = re.compile(r' (?P<bin>( [0-9a-f]{2}){1,16})\s+')

    def __init__(self, timeout):
      self._pipe = pexpect.spawn('bluetoothctl', encoding='utf-8', timeout=timeout.total_seconds())

    def scan(self):
        logging.debug('Scan started')
        self._pipe.sendline('scan on')
        self._pipe.expect('Discovery started')
        self._pipe.sendline('devices')
        lastevent = None
        while True:
            line = self._pipe.readline().strip()
            #print(line, file=sys.stderr)
            if evt := Controller.EVENT.search(line):
                data = evt.groupdict()
                if lastevent:
                    yield lastevent
                lastevent = Event(mac=data['mac'], key=data['key'], value=data['value'])
            elif attr := Controller.ATTR.search(line):
                data = attr.groupdict()
                if lastevent:
                    yield lastevent
                lastevent = Event(mac=data['mac'].replace('_', ':'), key=data['key'], value=None)
            elif ann := Controller.ANNOUNCE.search(line):
                data = ann.groupdict()
                yield Event(mac=data['mac'], key='Name', value=data['alias'])
            elif binary := Controller.DUMP.search(line):
                txt = binary.group(0).replace(' ', '')
                if lastevent.value:
                    lastevent.value += bytes.fromhex(txt)
                else:
                    lastevent.value = bytes.fromhex(txt)
                if len(lastevent.value) % 16 != 0:
                    yield lastevent
                    lastevent = None
            else:
                logging.debug(f'Unexpected line "{line}"')

    def connect(self, mac):
        logging.debug(f'Try to connect {mac}')
        self._pipe.sendline(f'connect {mac}')

    def disconnect(self):
        logging.debug('Disconnect current device')
        self._pipe.sendline('gatt.release-notify')
        self._pipe.sendline('disconnect')

    def select_notify(self, attr):
        logging.debug(f'Enable notifications from {attr}')
        self._pipe.sendline(f'gatt.select-attribute {attr}')
        self._pipe.sendline('gatt.acquire-notify')

def parse_rssi(val):
    return re.search(r'-\d+', val).group(0)

class MijiaDevice(object):
    @staticmethod
    def maybe_create(evt):
        return MijiaDevice(evt.mac) if evt.mac.startswith('4C:65:A8') else None

    def __init__(self, mac):
        logging.debug(f'Added Mijia device {mac}')
        self._mac = mac

    def parse_event(self, key, value):
        if key == 'RSSI':
            return [('rssi', parse_rssi(value))]
        elif key.startswith('ServiceData.0000fe95') or key == 'ServiceData Value':
            return MijiaDevice._parse_broadcast(value)
        else:
            return []

    # https://github.com/LynxyssCZ/node-xiaomi-gap-parser
    @staticmethod
    def _parse_broadcast(payload):
        ctrl, prod, ctr = struct.unpack('<HHB', payload[:5])
        if ctrl != 0x2050 or prod != 0x01aa:
            return []
        event, size = struct.unpack('<HB', payload[11:14])
        data = payload[14:14+size]
        if event == 0x100a:
            return [MijiaDevice._battery(data[0])]
        elif event == 0x1006:
            humi, = struct.unpack('<H', data)
            return [MijiaDevice._humidity(humi)]
        elif event == 0x1004:
            temp, = struct.unpack('<H', data)
            return [MijiaDevice._temperature(temp)]
        elif event == 0x100d:
            temp, humi = struct.unpack('<HH', data)
            return [MijiaDevice._temperature(temp), MijiaDevice._humidity(humi)]
        else:
            logging.debug(f'Unexpected mijia payload {payload.hex()}')
            return []

    @staticmethod
    def _battery(val):
        return ('battery', int(val))

    @staticmethod
    def _humidity(val):
        return ('humidity', val / 10.0)

    @staticmethod
    def _temperature(val):
        return ('temperature', val / 10.0)


class XSDevice(object):
    @staticmethod
    def maybe_create(evt):
        return XSDevice(evt.mac) if evt.key == 'Name' and evt.value.startswith('XS-') else None

    def __init__(self, mac):
        logging.debug(f'Added XS device {mac}')
        self._mac = mac

    def parse_event(self, key, value):
        if key == 'RSSI':
            return [('rssi', parse_rssi(value))]
        elif key.startswith('service000'):
            return XSDevice._parse_attribute(value)
        return []

    @staticmethod
    def _parse_attribute(payload):
        id, event, _ = struct.unpack('<BHB', payload[:4])
        if id != 0x23:
            return []
        data = payload[4:-1]
        if event == 0x1008:
            co2, tvoc, hcho = struct.unpack('>HHH', data)
            return [('co2', co2), ('tvoc', tvoc / 1000.0), ('hcho', hcho / 1000.0)]
        elif event == 0x1006:
            temp, humi = struct.unpack('>HH', data)
            return [('temperature', temp / 10.0), ('humidity', humi)]
        elif event == 0x1004:
            supplied, charge = struct.unpack('BB', data)
            return [('ac_connected', supplied), ('battery', charge)]
        else:
            logging.debug(f'Unexpected xs payload {payload.hex()}')
            return []

    def on_services_resolved(self, ctrl):
        ctrl.select_notify('0000c761-0000-1000-8000-00805f9b34fb')

class ConnectionStatus(object):
    MAX_CONNECTED = timedelta(seconds=30)
    RECONNECT_PERIOD = timedelta(minutes=2)

    def __init__(self):
        self._last_activity = datetime.fromtimestamp(0)
        self._devices = dict() # mac => status

    def connect(self, mac):
        self._devices[mac] = 'Connecting'

    def disconnect(self):
        for (mac, status) in self._devices.items():
            if status == 'Connected':
                self._devices[mac] = 'Disconnecting'

    def on_connected(self, mac):
        self._devices[mac] = 'Connected'
        self._update()

    def on_disconnected(self, mac):
        self._devices.pop(mac, None)
        self._update()

    def _update(self):
        self._last_activity = datetime.now()

    def may_connect(self, now):
        return len(self._devices) == 0 and self._is_expired(ConnectionStatus.RECONNECT_PERIOD, now)

    def need_disconnect(self, now):
        return 'Connected' in self._devices.values() and self._is_expired(ConnectionStatus.MAX_CONNECTED, now)

    def _is_expired(self, period, now = datetime.now()):
        return now - self._last_activity > period

class DevicesList(object):
    def __init__(self, ctrl):
        self._ctrl = ctrl
        self._devs = {}
        self._connectable = []
        self._status = ConnectionStatus()
        self._rr_index = -1

    def process_event(self, evt):
        self._dispatch_connections()
        if evt.mac not in self._devs:
            self._maybe_add_device(evt)
        if evt.mac in self._devs:
            if evt.key == 'Connected':
                self._process_connection(evt)
            elif evt.key == 'ServicesResolved':
                self._process_service_resolve(evt)
            else:
                return [(evt.mac, k, v) for k, v in self._devs[evt.mac].parse_event(evt.key, evt.value)]
        return []

    def _dispatch_connections(self):
        now = datetime.now()
        if self._status.need_disconnect(now):
            self._status.disconnect()
            self._ctrl.disconnect()
        elif self._status.may_connect(now):
            self._connect_next()

    def _maybe_add_device(self, evt):
        if mijia := MijiaDevice.maybe_create(evt):
            self._devs[evt.mac] = mijia
        elif xs := XSDevice.maybe_create(evt):
            self._devs[evt.mac] = xs
            self._connectable.append(xs)

    def _process_connection(self, evt):
        logging.debug(f'Connected {evt.mac}: {evt.value}')
        if evt.value == 'yes':
            self._status.on_connected(evt.mac)
        else:
            self._status.on_disconnected(evt.mac)

    def _process_service_resolve(self, evt):
        logging.debug(f'Resolved {evt.mac}: {evt.value}')
        if evt.value == 'yes':
            self._devs[evt.mac].on_services_resolved(self._ctrl)

    def _connect_next(self):
        candidates = len(self._connectable)
        if candidates == 0:
            return
        self._rr_index = (self._rr_index + 1) % candidates
        dev = self._connectable[self._rr_index]
        self._status.connect(dev._mac)
        self._ctrl.connect(dev._mac)

def listen(timeout):
    ctrl = Controller(timeout)
    devs = DevicesList(ctrl)
    for evt in ctrl.scan():
        for d in devs.process_event(evt):
            yield d

def debounce(stream, timeout):
    filt = {}
    for mac, type, val in stream:
        now = datetime.now()
        key = (mac, type)
        (prev, ts) = filt.get(key, (None, None))
        if prev == val and now - ts < timeout:
            logging.debug(f'Drop {mac}: {type}={val}')
        else:
            filt[key] = (val, now)
            yield (mac, type, val)

def scan_handler(src, handler):
    for mac, type, val in src:
        cmd = handler.format(mac=mac, type=type.lower(), value=val)
        res = call(cmd, shell=True)
        logging.debug('[%s] returned %u', cmd, res)

def scan_format(src, format):
    for mac, type, val in src:
        str = format.format(mac=mac, type=type.lower(), value=val)
        logging.debug(f"Emit '{str}'")
        print(str, flush=True)

def main():
    parser = ArgumentParser(description='Mijia scanning daemon')
    parser.add_argument('--verbose', action='store_true', help='Be verbose')
    parser.add_argument('--handler', help='Call specified binary with {{mac}},{{type}},{{value}} placeholders')
    parser.add_argument('--format', help='Format string with {{mac}},{{type}} and {{value}} placeholders and flush to stdout')
    parser.add_argument('--timeout', default=5, type=int, help='Timeout for no data in minutes')
    parser.add_argument('--debounce', default=0, type=int, help='Enable debounce of duplicated values for specified amount of seconds')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    src = listen(timedelta(minutes=args.timeout))
    if args.debounce:
        src = debounce(src, timedelta(seconds=args.debounce))

    if args.handler:
        scan_handler(src, args.handler)
    elif args.format:
        scan_format(src, args.format)
    else:
        raise 'Nor --handler neigher --format specified'

if __name__ == '__main__':
    main()
