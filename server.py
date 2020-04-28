from own_resp import OWNResponseGenerator, OWNEncryption
from tptp_resp import TptpResponseGenerator
from integrity import Integrity, Logger
from os import path, getcwd, system
from db_manager import DbManger
from datetime import datetime
from konfig import Config
from select import select
from socket import socket
import traceback
import time
import sys
import re


class TptpParser(Logger):
    def __init__(self):
        super().__init__()
        self.peer = None
        self.res_dict = dict()

    def parse_data(self, data, peer=None):
        """Request/response parsing function (input - bytes; output - bool)."""
        self.write_hex_in_log(data)
        try:
            def get_subfields(tag):
                if tag == 'a':
                    [self.res_dict.update({f'Sub field <{i[0]}>': i[1:]}) for i in re.findall(r'&(.*?)#', self.res_dict['Field <a>'])]
            if len(data) < 48: return None
            content = [d.decode('utf-8') for d in data[1:-2].split(b'\x1c')]
            header = content.pop(0)
            self.peer = peer
            self.res_dict = {
                'Device type': header[:2],
                'Transmission number': header[2:4],
                'Terminal ID': header[4:20],
                'Employee ID': header[20:26],
                'Current date': header[26:32],
                'Current time': header[32:38],
                'Message type': header[38:39],
                'Message sub type': header[39:40],
                'Transaction code': header[40:42],
                'Processing flag 1': header[42:43],
                'Processing flag 2': header[43:44],
                'Processing flag 3': header[44:45],
                'Response code': header[45:48]
            }
            if content: [self.res_dict.update({f'Field <{field[0]}>': field[1:]}) for field in content]
            if 'Field <a>' in self.res_dict: get_subfields('a')
            if peer: return self.req_test(data)
            else: return True
        except UnicodeDecodeError:
            self.console_print(f"Error appeared in process of parsing income data from {peer}!", level='ERROR')
            self.console_print(r"Please go to src\srv_settings.ini and check 'PROTOCOL' value.", level='WARNING')
            self.write_in_log(f"Error appeared in process of parsing income data from {peer}!", level='ERROR')
            return None

    def req_test(self, request):
        """Error detection in request (input - bytes; output - bool)."""
        def is_mtype_legal():
            return self.res_dict['Message type'] in ['A', 'F', 'I', 'U']

        def is_lrc_legal():
            return ord(TptpParser.find_lrc(request, req_flag=True)) == request[-1]

        def is_dtype_legal():
            return self.res_dict['Device type'] == '9.' or self.res_dict['Device type'] == '9R'

        def is_msubtype_legal():
            return self.res_dict['Message sub type'] in ['A', 'T', 'R', 'M', 'U', 'P', 'C', 'O', 'F', 'S', 'E']

        def is_pr_flag_legal():
            pf1, pf2 = int(self.res_dict['Processing flag 1']), int(self.res_dict['Processing flag 2'])
            try: return pf1 in range(2) and pf2 in range(2)
            except ValueError: return False

        def is_trans_num_legal():
            try: return int(self.res_dict['Transmission number']) in range(100)
            except ValueError: return False

        def is_trans_code_legal():
            try: return int(self.res_dict['Transaction code']) in range(100)
            except ValueError: return False

        try:
            assert is_lrc_legal(), 'Wrong lrc'
            assert is_dtype_legal(), 'Wrong device type'
            assert is_mtype_legal(), 'Wrong message type'
            assert is_pr_flag_legal(), 'Wrong processing flag'
            assert is_msubtype_legal(), 'Wrong message sub type'
            assert is_trans_code_legal(), 'Wrong transaction code'
            assert is_trans_num_legal(), 'Wrong transmission number'
            return True
        except AssertionError as e:
            self.write_in_log(''.join([str(e), f' in request from {self.peer}']), level='ERROR')
            self.console_print(''.join([str(e), f' in request from {self.peer}']), level='ERROR')
            return False

    @staticmethod
    def find_lrc(data, lrc=0, req_flag=False):
        """Finds lrc of request/response (input - bytes; output - str)."""
        if req_flag: data = data[1:-1]
        for symbol in data: lrc ^= symbol
        return chr(lrc)

    @staticmethod
    def print_parsed_data(parsed_dict):
        for i in parsed_dict: print('>{:20}: {}'.format(i, parsed_dict[i]))

    def write_hex_in_log(self, data, counter=0):
        dump = list()
        for i in data:
            if counter % 32 == 0: dump.append('\n')
            dump.append(hex(i).replace('0x', '').zfill(2))
            counter += 1
        self.write_in_log(' '.join(dump))


class OWNParser(Logger):
    def __init__(self):
        super().__init__()
        self.bitmap = list()
        self.res_dict = dict()

    def parse_data(self, data):
        self.write_hex_in_log(data)
        self.read_bitmap(data[4:12])
        self.res_dict = {
            'Message type': OWNParser.convert_bytes_to_str(data[2:4]),
            'Bitmap': OWNParser.convert_bytes_to_str(data[4:12]),
        }
        if not self.add_fields_to_res_dict(data): return False
        return True

    def add_fields_to_res_dict(self, data, start=12):
        numeric_flist = [2]
        len_dict = {'2': 'LLVAR', '3': 3, '4': 6, '7': 5, '11': 3, '12': 3, '13': 2, '14': 2, '22': 2, '23': 2,
                    '24': 2, '25': 1, '35': 'LLVAR', '37': 12, '38': 6, '39': 2, '41': 8, '42': 15,
                    '48': 'LLLVAR', '49': 2, '52': 8, '55': 'LLLVAR', '60': 'LLLVAR', '61': 'LLLLVAR', '63': 'LLLVAR', '64': 4}
        for field in self.bitmap:
            try:
                f_length = len_dict[str(field)]
                if type(f_length) == int:
                    self.res_dict.update({f'Field <{str(field)}>': OWNParser.prettify(field, data[start: f_length + start])})
                    start += f_length
                elif type(f_length) == str:
                    if f_length == 'LLVAR':
                        if field in numeric_flist: length = int(OWNParser.convert_bytes_to_str(data[start: start + 1])) // 2
                        else: length = int(OWNParser.convert_bytes_to_str(data[start: start + 1]))
                        self.res_dict.update({f'Field <{str(field)}>': OWNParser.prettify(field, data[start + 1: length + start + 1])})
                        start += length + 1
                    elif f_length == 'LLLVAR':
                        length = int(OWNParser.convert_bytes_to_str(data[start: start + 2]))
                        self.res_dict.update({f'Field <{str(field)}>': OWNParser.prettify(field, data[start + 2: length + start + 2])})
                        start += length + 2
                    elif f_length == 'LLLLVAR':
                        length = int(OWNParser.convert_bytes_to_str(data[start: start + 3]))
                        self.res_dict.update({f'Field <{str(field)}>': OWNParser.prettify(field, data[start + 3: length + start + 3])})
                        start += length + 3
                else: pass
            except KeyError:
                self.console_print(f"Can't parse field <{str(field)}>", level='ERROR')
                self.write_in_log(f"Can't parse field <{str(field)}>", level='ERROR')
                return False
            except ValueError: pass
        return True

    def read_bitmap(self, bitmap):
        self.bitmap = list()
        bin_list = [bin(i).replace('0b', '').zfill(8) for i in bitmap]
        for i in range(len(bin_list)):
            for j in range(len(bin_list[i])):
                if bin_list[i][j] == '1': self.bitmap.append(i * 8 + j + 1)

    @staticmethod
    def prettify(field, value):
        bytes_fields = [2, 3, 4, 7, 11, 12, 13, 14, 22, 23, 25, 24, 48, 49, 52, 55, 61, 64]
        try:
            if field in bytes_fields:
                return OWNParser.convert_bytes_to_str(value).upper()
            else: return value.decode('utf-8')
        except UnicodeDecodeError:
            return value

    @staticmethod
    def convert_bytes_to_str(dump):
        return ''.join([hex(i).replace('0x', '').zfill(2) for i in dump])

    @staticmethod
    def print_parsed_data(parsed_dict):
        for i in parsed_dict: print('>{:20}: {}'.format(i, parsed_dict[i]))

    def write_hex_in_log(self, data, counter=0):
        dump = list()
        for i in data[2:]:
            if counter % 32 == 0: dump.append('\n')
            dump.append(hex(i).replace('0x', '').zfill(2))
            counter += 1
        self.write_in_log(' '.join(dump))


class Server(DbManger):
    def __init__(self, version=None):
        def server_init(srv_address=None):
            try:
                self.get_srv_settings()
                self.console_print(f'Current log-file - {self.filename}')
                srv_address = (self.get_server_option('SERVER_IP'), self.get_server_option('SERVER_PORT'))

                self.srv = socket()
                self.srv.setblocking(False)
                self.srv.bind(srv_address)
                self.srv.listen(10)

                self.INPUT.append(self.srv)
                self.console_print(f'Server started on {str(srv_address)}')
                self.write_in_log(f'Server started on {srv_address}')
                self.print_parsed = self.get_server_option('PRINT_PARSED')
                self.protocol = self.get_server_option('PROTOCOL').upper()
                self.own_encryption = self.get_server_option('OWN_ENCRYPTION')
            except OSError:
                self.write_in_log(f"Can't start server on address/port = {srv_address}", level='ERROR')
                self.console_print(f"Can't start server on address/port = {srv_address}", level='ERROR')
                self.close_server()
            except KeyError:
                self.write_in_log('File srv_settings.ini is damaged! One of server ip/port is not present!', level='ERROR')
                self.console_print('File srv_settings.ini is damaged! One of server ip/port is not present!', level='ERROR')
                self.console_print('Go to /src/srv_settings.ini, delete this file and run server.exe.')
                self.close_server()
            except TypeError and AttributeError:
                self.write_in_log(f"Can't start server!", level='ERROR')
                self.console_print(f"Can't start server!", level='ERROR')
                self.close_server()

        def vars_init():
            self.INPUT = list()
            self.OUTPUT = list()
            self.version = version
            self.req_dict = dict()
            self.encoder_list = list()
            self.srv_settings = dict()
            self.tptp_rc_dict = dict()
            self.clear_req_dict = dict()

        def parser_init():
            self.own_encrypt = OWNEncryption()
            self.own_parser = OWNParser()
            self.tptp_parser = TptpParser()

        def resp_gen_init():
            self.emulator = self.get_server_option('EMULATOR_MODE')
            self.own_generator = OWNResponseGenerator(emulator=True)
            self.tptp_generator = TptpResponseGenerator(self.tptp_rc_dict, emulator=self.emulator)

        def integrity_init():
            self.integrity = Integrity()
            self.integrity.exam()

        def timer_init():
            self.ignore_dict = dict()
            time.perf_counter()

        integrity_init()
        super().__init__()
        vars_init()
        timer_init()
        server_init()
        parser_init()
        resp_gen_init()
        self.run_server()

    def run_server(self):
        """Main cycle of server."""
        try:
            self.console_print(f'POS Test Server {self.version}')
            while self.INPUT:
                readables, writables, exceptional = select(self.INPUT, self.OUTPUT, self.INPUT)
                self.handle_readables(readables)
                self.handle_writables(writables)
        except KeyboardInterrupt:
            self.write_in_log('Server stopped!')
            self.close_connect(self.srv, flag=False)
            self.console_print('Server stopped!')

    def is_conn_ready(self, peer):
        current_time = time.perf_counter()
        if peer in self.ignore_dict:
            if current_time >= self.ignore_dict[peer]:
                self.ignore_dict.pop(peer)
                return True
            else: return False
        else: return True

    def handle_readables(self, reads):
        """Solving income data function. Also this function responsible for accepting new connection."""
        def process_tptp_data():
            if len(data) >= 48:
                if self.tptp_parser.parse_data(data, peer=peer):
                    op_name = '-'.join([self.tptp_parser.res_dict['Transaction code'],
                                        self.tptp_parser.res_dict['Message type'],
                                        self.tptp_parser.res_dict['Message sub type']])
                    val = self.get_value_from_ignore_list(op_name)
                    if val != 0:
                        if peer in self.ignore_dict: self.ignore_dict[peer] = time.perf_counter() + val
                        else: self.ignore_dict.update({peer: time.perf_counter() + val})

                    if self.print_parsed: TptpParser.print_parsed_data(self.tptp_parser.res_dict)
                if peer not in self.req_dict: self.req_dict.update({peer: self.tptp_parser.res_dict})
                else: self.req_dict[peer] = self.tptp_parser.res_dict
            else:
                if peer not in self.req_dict: self.req_dict.update({peer: '<ACK>'})
                else: self.req_dict[peer] = '<ACK>'

        def process_own_data():
            if self.own_encryption and not (data[2:4] == b'\x08\x00' and data[12:15] == b'\x96\x00\x00'):
                clear_data = self.own_encrypt.decode(data)
                self.encoder_list.append(peer)
            else: clear_data = data

            if clear_data:
                if self.own_parser.parse_data(clear_data):
                    if self.print_parsed: OWNParser.print_parsed_data(self.own_parser.res_dict)

                    if peer not in self.req_dict: self.req_dict.update({peer: self.own_parser.res_dict})
                    else: self.req_dict[peer] = self.own_parser.res_dict

                    if peer not in self.clear_req_dict: self.clear_req_dict.update({peer: clear_data})
                    else: self.clear_req_dict[peer] = clear_data
                else:
                    self.console_print(f'Error appeared in process of parsing!', level='ERROR')
                    self.write_in_log(f'Error appeared in process of parsing!', level='ERROR')

        for resource in reads:
            if resource is self.srv:
                conn, addr = resource.accept()
                conn.setblocking(False)
                self.INPUT.append(conn)
                self.console_print(f'New connection:{str(addr)}')
                self.write_in_log(f'New connection:{str(addr)}')

                if self.protocol == 'TPTP': conn.send(b'\x05')
            else:
                data = bytes()
                try: data = resource.recv(1024)
                except ConnectionResetError: pass
                except ConnectionAbortedError: pass

                if data:
                    peer = resource.getpeername()
                    self.console_print(f'Request from {peer}:{data}')
                    self.write_in_log(f'Request from {peer}:{data}')
                    if resource not in self.OUTPUT: self.OUTPUT.append(resource)

                    if self.protocol == 'TPTP': process_tptp_data()
                    elif self.protocol == 'OWN': process_own_data()

    def handle_writables(self, writs):
        for resource in writs:
            tdk_key = None
            peer = resource.getpeername()
            if self.protocol == 'TPTP':
                if peer in self.req_dict:
                    if self.req_dict[peer] == '<ACK>':
                        resp = b'\x04'
                        self.write_in_log(f'Response to  {peer}:{resp}')
                        self.console_print(f'Response to  {peer}:{resp}')
                        resource.send(resp)
                        self.OUTPUT.remove(resource)
                    else:
                        try:
                            if self.is_conn_ready(peer):
                                try: resp = self.tptp_generator.get_response(self.req_dict.pop(peer))
                                except KeyError: resp = None
                                if resp:
                                    resp = b''.join([b'\x02', resp, b'\x03', TptpParser.find_lrc(b''.join([resp, b'\x03'])).encode('utf-8')])
                                    self.write_in_log(f'Response to  {peer}:{resp}')
                                    self.console_print(f'Response to  {peer}:{resp}')
                                    resource.send(resp)
                                    self.OUTPUT.remove(resource)

                                    if self.tptp_parser.parse_data(resp, peer=peer) and self.print_parsed:
                                        TptpParser.print_parsed_data(self.tptp_parser.res_dict)
                        except OSError:
                            self.write_in_log(traceback.format_exc(), level='ERROR')
                            self.close_connect(resource)
            elif self.protocol == 'OWN':
                try: resp, tdk_key = self.own_generator.get_response(self.req_dict.pop(peer), self.clear_req_dict.pop(peer))
                except KeyError: resp = None

                if resp:
                    if self.own_parser.parse_data(resp):
                        term_id = self.own_parser.res_dict['Field <41>'] if 'Field <41>' in self.own_parser.res_dict else None
                        if term_id:
                            if self.own_encryption and peer in self.encoder_list:
                                self.encoder_list.pop(self.encoder_list.index(peer))
                                resp = self.own_encrypt.encode(resp, term_id, tdk_key)
                            if resp:
                                self.write_in_log(f'Response to  {peer}:{resp}')
                                self.console_print(f'Response to  {peer}:{resp}')
                                resource.send(resp)
                                self.OUTPUT.remove(resource)
                                if self.print_parsed: OWNParser.print_parsed_data(self.own_parser.res_dict)

    def close_connect(self, connect, flag=True):
        if connect in self.INPUT: self.INPUT.remove(connect)
        if connect in self.OUTPUT: self.OUTPUT.remove(connect)
        if flag:
            self.console_print(f'Connection closed:{str(connect.getpeername())}')
            self.write_in_log(f'Connection closed:{str(connect.getpeername())}')
        connect.close()

    def get_srv_settings(self):
        """Converts config settings into python dict()"""
        config = Config(path.join(getcwd(), 'src', 'srv_settings.ini')).as_args()
        [self.srv_settings.update({config[i * 2][2:]: config[i * 2 + 1]}) for i in range(len(config) // 2)]
        for st_name in self.srv_settings:
            try:
                self.tptp_rc_dict.update({'-'.join(st_name.split('-')[2:]): str(int(self.srv_settings[st_name])).zfill(3)})
            except ValueError: raise Exception(f'Wrong value in settings, line - {st_name}')

    def close_server(self):
        self.console_print('Press ENTER to exit.')
        input(); sys.exit()


if __name__ == '__main__':
    system('cls')
    server = Server(version='v0.0.6')
