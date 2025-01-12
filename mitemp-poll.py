#!/usr/bin/python3

from argparse import ArgumentParser
import pexpect
import time
from datetime import datetime, timedelta
import logging
import os
from random import randint
import re
import struct
from subprocess import call
import sys
import threading
from threading import Thread, Lock

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
    DUMP = re.compile(r' (?P<bin>( [0-9a-f]{2}){1,16})\s+')

    def __init__(self):
        self._pipe = pexpect.spawn('bluetoothctl', encoding='utf-8', timeout=300)

    def scan(self):
        logging.debug('Scan started')
        self._pipe.sendline('scan on')
        self._pipe.expect('Discovery started')
        self._pipe.sendline('devices')

    def listen(self):
        lastevent = None
        while True:
            line = self._pipe.readline().strip()
            if evt := Controller.EVENT.search(line):
                data = evt.groupdict()
                if lastevent:
                    yield lastevent
                lastevent = Event(mac=data['mac'], key=data['key'], value=data['value'])
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

def connect_gatt(mac, handle, val):
    if not hasattr(connect_gatt, 'lock'):
        connect_gatt.lock = Lock()
    with connect_gatt.lock:
        pipe = pexpect.spawn(f'gatttool -b {mac} --char-write-req --handle={handle} --value={val} --listen', encoding='utf-8')
        idx = pipe.expect([pexpect.EOF, pexpect.TIMEOUT, r'written successfully'], timeout=randint(30, 60))
        if idx < 2:
            pipe.terminate(force=True)
            return None
        return pipe

def listen_notifications(mac, handle, val):
    if not hasattr(listen_notifications, 'lock'):
        listen_notifications.lock = Lock()
    logger = logging.getLogger(mac)
    while True:
        logger.debug('Connect')
        pipe = connect_gatt(mac, handle, val)
        if not pipe:
            continue
        logger.debug('Listen events')
        while True:
            idx = pipe.expect([pexpect.EOF, pexpect.TIMEOUT,
                               r'error\r\n',
                               r'Notification handle = (?P<handle>0x[0-9a-f]+) value:(?P<bin>( [0-9a-f]{2})+)\s*\r\n'], timeout=randint(30, 60))
            if idx < 3:
                logger.debug('Restart')
                pipe.terminate(force=True)
                break
            match = pipe.match.groupdict()
            logger.debug(f"Notified {match['handle']}={match['bin']}")
            txt = match['bin'].replace(' ', '')
            yield bytes.fromhex(txt)

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
        else:
            return []

    def scan(self, dst):
        for payload in listen_notifications(self._mac, '0x000d', '0x2'):
            for k, v in XSDevice._parse_notification(payload):
                dst(self._mac, k, v)

    @staticmethod
    def _parse_notification(payload):
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

class DevicesList(object):
    def __init__(self, ctrl):
        self._ctrl = ctrl
        self._devs = {}

    def start(self, dst):
        self._ctrl.scan()
        for evt in self._ctrl.listen():
            self._process_event(evt, dst)

    def _process_event(self, evt, dst):
        if evt.mac not in self._devs:
            self._maybe_add_device(evt, dst)
        if evt.mac in self._devs:
            for k, v in self._devs[evt.mac].parse_event(evt.key, evt.value):
                dst(evt.mac, k, v)

    def _maybe_add_device(self, evt, dst):
        if mijia := MijiaDevice.maybe_create(evt):
            self._devs[evt.mac] = mijia
        elif xs := XSDevice.maybe_create(evt):
            self._devs[evt.mac] = xs
            Thread(name=f'Scanner for {evt.mac}', target=lambda: xs.scan(dst)).start()

class Handler(object):
    def __init__(self, handler):
        self._handler = handler

    def __call__(self, mac, type, value):
        cmd = self._handler.format(mac=mac, type=type.lower(), value=value)
        res = call(cmd, shell=True)
        logging.debug('[%s] returned %u', cmd, res)

class Format(object):
    def __init__(self, format):
        self._format = format

    def __call__(self, mac, type, value):
        str = self._format.format(mac=mac, type=type.lower(), value=value)
        logging.debug(f"Emit '{str}'")
        print(str, flush=True)

class Debouncer(object):
    def __init__(self, delegate, timeout):
        self._delegate = delegate
        self._timeout = timeout
        self._buffer = dict()
        self._lock = Lock()

    def __call__(self, mac, type, value):
        with self._lock:
            now = datetime.now()
            if len(self._buffer) == 0:
                self._next_flush = now + self._timeout
            self._buffer[(mac, type)] = value
            if now > self._next_flush:
                for (m, t), v in self._buffer.items():
                    self._delegate(m, t, v)
                self._buffer.clear()

def main():
    parser = ArgumentParser(description='Mijia scanning daemon')
    parser.add_argument('--verbose', action='store_true', help='Be verbose')
    parser.add_argument('--handler', help='Call specified binary with {{mac}},{{type}},{{value}} placeholders')
    parser.add_argument('--format', help='Format string with {{mac}},{{type}} and {{value}} placeholders and flush to stdout')
    parser.add_argument('--debounce', default=0, type=int, help='Enable debounce of duplicated values for specified amount of seconds')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if args.handler:
        dst = Handler(args.handler)
    elif args.format:
        dst = Format(args.format)
    else:
        raise 'Nor --handler neigher --format specified'
    if args.debounce:
        dst = Debouncer(dst, timedelta(seconds=args.debounce))

    ctrl = Controller()
    devs = DevicesList(ctrl)
    devs.start(dst)

if __name__ == '__main__':
    main()
