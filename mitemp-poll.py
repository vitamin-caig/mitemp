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


'''
Represents hardware bluetooth interface
'''
class Interface(object):
    def __init__(self, addr):
        self.__logger = logging.getLogger(addr)
        self.__addr = addr

    def get_name(self):
        return self.__addr

    def get_socket(self, mac):
        pipe = pexpect.spawn('gatttool -i {} -b {} -I'.format(self.__addr, mac), encoding='utf-8')
        return Socket(pipe, self.__logger.getChild(mac))

    def reset(self):
        self.__logger.debug('Reset')
        call(['hciconfig', self.__addr, 'reset'])

    def scan(self, mask):
        self.__logger.debug('Scan')
        child = pexpect.spawn('hcitool -i {} lescan --passive'.format(self.__addr), encoding='utf-8')
        while True:
            idx = child.expect([mask, 'Set scan parameters failed: Input/output error', pexpect.EOF, pexpect.TIMEOUT], timeout=60)
            if 0 == idx:
                yield child.match.group(0)
            elif 1 == idx:
                self.reset()
                break
            else:
                break

'''
Represents logical connection to some particular bluetooth device
'''
class Socket(object):
    def __init__(self, pipe, logger):
        self.__child = pipe
        self.__logger = logger

    def connect(self):
        self.__logger.debug('Connect')
        while True:
            self.__child.sendline('connect')
            if 0 == self.__child.expect(['Connection successful', pexpect.TIMEOUT], timeout=20):
                break

    def read_handle_bytes(self, hnd):
        self.__logger.debug('Read bytes from %s', hnd)
        self.__child.sendline('char-read-hnd {}'.format(hnd))
        self.__child.expect('Characteristic value/descriptor: ', timeout=10)
        self.__child.expect('\r\n', timeout=10)
        return self.__read_array()

    def __read_array(self):
        self.__logger.debug('received %s', self.__child.before)
        return [int(val, 16) for val in self.__child.before.split()]

    def read_handle_strings(self, hnd, notifhnd):
        self.__logger.debug('Read strings from %s', hnd)
        self.__child.sendline('char-write-req {} 0100'.format(hnd))
        self.__child.expect('Characteristic value was written successfully', timeout=20)
        reply = 'Notification handle = {} value: '.format(notifhnd)
        res = []
        while 0 == self.__child.expect([reply, pexpect.TIMEOUT if 0 != len(res) else pexpect.EOF], timeout=10):
            self.__child.expect('\r\n', timeout=10)
            res.append(''.join(map(chr, self.__read_array())))
        return res

    def disconnect(self):
        self.__logger.debug('disconnect')
        self.__child.sendline('disconnect')
        self.__child.sendline('exit')


'''
Represents MijiaDevice (lLYWSDCGQ/01ZM)
'''
class MijiaDevice(object):
    #  standard mac prefix for all Mijia devices
    MAC_ADDRESS_MASK = '4C:65:A8:..:..:..'
    RETRIES = 5
    RETRY_DELAY_MAX = 10
    BATTERY_HANDLE = '0x18'
    TEMP_HUMID_HANDLE = '0x10'
    TEMP_HUMID_NOTIFHANDLE = '0x000e'

    def __init__(self, iface, mac):
        self.__logger = logging.getLogger('Mijia[{}]'.format(mac))
        self.__iface = iface
        self.__mac = mac

    def get_full_addr(self):
        return self.__iface.get_name() + '.' + self.__mac

    def get_addr(self):
        return self.__mac

    def get_data(self):
        for retry in range(MijiaDevice.RETRIES, 0, -1):
            try:
                return self.__read()
                break
            except pexpect.exceptions.TIMEOUT as e:
                if retry == 1:
                    raise e
                else:
                    self.__logger.debug('Timeout. Retry refresh. %u tries left', retry)
                    time.sleep(MijiaDevice.RETRY_DELAY_MAX - retry)

    def __read(self):
        sock = self.__iface.get_socket(self.__mac)
        sock.connect()
        #  Single byte
        bat = sock.read_handle_bytes(MijiaDevice.BATTERY_HANDLE)[0]
        #  Array of string in ' T=AA.B H=CC.D' form
        temp, humid = MijiaDevice.__parse_th(sock.read_handle_strings(MijiaDevice.TEMP_HUMID_HANDLE, MijiaDevice.TEMP_HUMID_NOTIFHANDLE))
        stamp = int(datetime.utcnow().timestamp())
        sock.disconnect()
        return {'Battery': bat, 'Temperature': temp, 'Humidity': humid, 'Timestamp': stamp}

    '''
    Get average values from several result lines keeping the same resolution
    '''
    @staticmethod
    def __parse_th(lines):
        temp = float(0)
        humid = float(0)
        for l in lines:
            t, h = MijiaDevice.__parse_th_line(l)
            temp += t
            humid += h
        count = len(lines)
        return round(temp / count, 1), round(humid / count, 1)

    @staticmethod
    def __parse_th_line(line):
        #  T=AA.B H=CC.D
        t, h = line.replace('T=', '').replace('H=', '').rstrip(' \t\r\n\0').split()
        return float(t), float(h)


'''
Async worker for particular device
'''
class Poller(object):
    def __init__(self, dev, statesdir, period):
        self.__logger = logging.getLogger('{}.Poller'.format(dev.get_full_addr()))
        self.__dev = dev
        self.__file = os.path.join(statesdir, dev.get_addr())
        self.__period = period

    def run(self):
        start = datetime.now()
        while True:
            self.__update_file()
            finish = datetime.now()
            next = start + self.__period
            if next > finish:
                pause = (next - finish).total_seconds()
                self.__logger.debug('Sleep for %ds', pause)
                time.sleep(pause)
            start = next

    def __update_file(self):
        data = self.__dev.get_data()
        self.__logger.debug('Update %s', self.__file)
        with open(self.__file, 'w') as f:
            for name, val in data.items():
                print('{}={}'.format(name, val), file=f)


class Scanner(object):
    def __init__(self, iface, statesdir, period):
        self.__logger = logging.getLogger('{}.Scanner'.format(iface.get_name()))
        self.__iface = iface
        self.__statesdir = statesdir
        self.__period = period
        self.__workers = {}

    def start(self):
        while True:
            self.__do_scan()
            self.__cleanup_dead()

    def __do_scan(self):
        for mac in self.__iface.scan(MijiaDevice.MAC_ADDRESS_MASK):
            self.__scan_device(mac)

    def __scan_device(self, mac):
        return self.__ensure_alive(mac) or self.__start_scanner(mac)

    def __ensure_alive(self, mac):
        prev = self.__workers.get(mac, None)
        if prev:
            if prev.is_alive():
                self.__logger.debug('Alive %s', mac)
                return True
            self.__logger.debug('Dead %s', mac)
            prev.join()
            del self.__workers[mac]
        return False

    def __start_scanner(self, mac):
            dev = MijiaDevice(self.__iface, mac)
            poll = Poller(dev, self.__statesdir, self.__period)
            proc = Process(target=poll.run)
            proc.start()
            self.__workers[mac] = proc

    def __cleanup_dead(self):
        new_workers = {}
        for mac, job in self.__workers.items():
            if job.is_alive():
                new_workers[mac] = job
            else:
                self.__logger.debug('Cleanup %s', mac)
                job.join()
        self.__workers = new_workers


def main():
    parser = ArgumentParser(description='Mijia scanning daemon')
    parser.add_argument('--interface', default='hci0', help='Bluetooth device to scan')
    parser.add_argument('--result-dir', default='/tmp/mijia', help='Directory to store polling results')
    parser.add_argument('--period', default=1, type=int, help='Scan period in minutes')
    parser.add_argument('--verbose', action='store_true', help='Be verbose')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    iface = Interface(args.interface)
    scan = Scanner(iface, args.result_dir, timedelta(minutes=args.period))
    scan.start()

if __name__ == '__main__':
    main()
