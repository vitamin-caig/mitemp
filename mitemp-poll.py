#!/usr/bin/python3

from argparse import ArgumentParser
import pexpect
import time
from datetime import datetime, timedelta
import logging
import os
import re
from subprocess import call
from multiprocessing import Process


def listen(timeout):
    logging.debug('Listen')
    pipe = pexpect.spawn('bluetoothctl', encoding='utf-8')
    pipe.sendline('scan on')
    pipe.expect('Discovery started')
    while True:
        idx = pipe.expect(['50 20 aa 01 .. (.. .. .. a8 65 4c) 0a 10 01 (..)', 
                           '50 20 aa 01 .. (.. .. .. a8 65 4c) 06 10 02 (..) (..)',
                           '50 20 aa 01 .. (.. .. .. a8 65 4c) 04 10 02 (..) (..)',
                           pexpect.EOF, pexpect.TIMEOUT], timeout=timeout.total_seconds())
        if idx >= 3:
            break;
        match = pipe.match
        mac = ':'.join(reversed(match.group(1).split(' '))).upper()
        lo = int(match.group(2), 16)
        if 0 == idx:
            yield (mac, 'Battery', lo)
        elif 1 == idx or 2 == idx:
            hi = int(match.group(3), 16)
            val = float(256 * hi + lo) / 10
            yield (mac, 'Humidity' if 1 == idx else 'Temperature', val)
    pipe.sendline('exit')
    pipe.wait()


class Device(object):
    def __init__(self, mac, statesdir):
        self.__logger = logging.getLogger(mac)
        self.__file = os.path.join(statesdir, mac)
        self.__data = {}
        self.__logger.debug('Created')

    def update(self, type, ts, value):
        self.__logger.debug('%s=%f', type, value)
        self.__data[type] = value
        self.__data['Timestamp'] = ts.timestamp()

    def dump(self):
        self.__logger.debug('Update %s', self.__file)
        with open(self.__file, 'w') as f:
            for name, val in self.__data.items():
                print('{}={}'.format(name, val), file=f)

    def updated_since(self, ts):
        return self.__data.get('Timestamp', 0) >= ts.timestamp()

    def delete(self):
        self.__logger.debug('Cleanup')
        os.remove(self.__file)


class Scanner(object):
    def __init__(self, statesdir, period, ttl):
        self.__statesdir = statesdir
        self.__period = period
        self.__ttl = ttl
        self.__devices = {}
        os.makedirs(statesdir, exist_ok=True)
        for mac in os.listdir(statesdir):
            self.__devices[mac] = Device(mac, self.__statesdir)

    def start(self):
        last_check = datetime.now()
        next_check = last_check + self.__period
        while True:
            for mac, type, val in listen(self.__period):
                dev = self.__devices[mac] if mac in self.__devices else self.__devices.setdefault(mac, Device(mac, self.__statesdir))
                ts = datetime.now()
                dev.update(type, ts, val)
                if ts >= next_check:
                    self.__dump_updated(last_check)
                    self.__cleanup_dead(last_check - self.__ttl)
                    last_check = ts
                    next_check = last_check + self.__period

    def __dump_updated(self, ts):
        for mac, device in self.__devices.items():
            if device.updated_since(ts):
                device.dump()

    def __cleanup_dead(self, ts):
        new_devices = {}
        for mac, device in self.__devices.items():
            if device.updated_since(ts):
                new_devices[mac] = device
            else:
                device.delete()
        self.__devices = new_devices


def scan_handler(handler, timeout):
    for mac, type, val in listen(timeout):
        cmd = handler.format(mac=mac, type=type.lower(), value=val)
        res = call(cmd, shell=True)
        logging.debug('[%s] returned %u', cmd, res)

def main():
    parser = ArgumentParser(description='Mijia scanning daemon')
    parser.add_argument('--result-dir', default='/tmp/mijia', help='Directory to store polling results')
    parser.add_argument('--period', default=1, type=int, help='Scan period in minutes')
    parser.add_argument('--ttl', default=5, type=int, help='Cleanup devices with no data after specified timeout minutes')
    parser.add_argument('--verbose', action='store_true', help='Be verbose')
    parser.add_argument('--handler', help='Call specified binary with {{mac}},{{type}},{{value}} placeholders')
    parser.add_argument('--timeout', default=5, type=int, help='Timeout for no data')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if args.handler:
        scan_handler(args.handler, timedelta(minutes=args.timeout))
    else:
        scan = Scanner(args.result_dir, timedelta(minutes=args.period), timedelta(minutes=args.ttl))
        scan.start()

if __name__ == '__main__':
    main()
