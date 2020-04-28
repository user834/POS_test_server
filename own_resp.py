from datetime import datetime, timedelta
from Crypto.Cipher import DES3, DES
from db_manager import DbManger
from binascii import unhexlify
from random import randint
import traceback


class OWNEncryption(DbManger):
    def __init__(self):
        super().__init__()
        self.conv_res = list()

    def encode(self, data, term_id, tdk_key):
        timestamp = OWNEncryption.get_timestamp()
        block_0 = hex(randint(0, 4294967295)).replace('0x', '')
        raw_block_1 = OWNEncryption.xor(OWNEncryption.xor(block_0, timestamp[:8]),
                                        ''.join([timestamp[8:12], '0000'])).upper()
        block_1 = ''.join([hex(ord(i)).replace('0x', '').zfill(2) for i in raw_block_1])
        data = b''.join([data[2:], b'\x80'])
        data = b''.join([data, b''.join([b'\x00' for _ in range(64 - len(data) % 64)])])

        additional = b''.join([term_id.encode('utf-8'), b'\x01\x0214'])
        descriptor = b'\x0a\x0c\x00\x04'

        if self.is_acquirer_present(term_id):
            if tdk_key:
                key = tdk_key
            else:
                key = self.get_key_from_db(term_id, 'TDK')

            if key:
                cypher = DES3.new(unhexlify(key), mode=DES3.MODE_ECB)
                left_part = cypher.encrypt(unhexlify(block_1)).hex()
                full_key = DES3.new(unhexlify(''.join([left_part, timestamp])),
                                    mode=DES3.MODE_CBC, IV=unhexlify(timestamp))

                result = b''.join([descriptor, self.convert_string_to_bytes(block_0), self.convert_string_to_bytes(timestamp),
                                   additional, full_key.encrypt(data)])
                length = self.convert_string_to_bytes(hex(len(result)).replace('0x', '').zfill(4))
                return b''.join([length, result])
            else:
                self.console_print(f"There's no TDK key in database for Terminal ID = '{blocks['term_id']}'!", level='ERROR')
                self.write_in_log(f"There's no TDK key in database for Terminal ID = '{blocks['term_id']}'!", level='ERROR')
                self.console_print(f"At first you should download keys in terminal.", level='WARNING')
        else:
            self.console_print(f"There's no Terminal ID = '{blocks['term_id']}' in 'acquirer_data' table!", level='ERROR')
            self.write_in_log(f"There's no Terminal ID = '{blocks['term_id']}' in 'acquirer_data' table!", level='ERROR')
        return None

    def decode(self, data):
        blocks = {
            'term_id': data[18:26].decode('utf-8'),
            'descriptor': data[2:6].hex(),
            'block_0': data[6:10].hex(),
            'block_2': data[10:18].hex()
        }
        legal_stamps = [''.join([OWNEncryption.get_timestamp(datetime.now() + timedelta(minutes=i))[:-4],
                                 '0000']) for i in range(-1, 2)]
        try:
            assert ''.join([blocks['block_2'][:-4], '0000']) in legal_stamps
        except AssertionError:
            self.console_print(f"Illegal incoming timestamp!", level='ERROR')
            self.write_in_log(f"Illegal incoming timestamp!", level='ERROR')
            self.console_print(f"Adjust time settings on the terminal.", level='WARNING')
            return None

        raw_block_1 = OWNEncryption.xor(OWNEncryption.xor(blocks['block_0'], blocks['block_2'][:8]),
                                        ''.join([blocks['block_2'][8:12], '0000'])).upper()
        blocks.update({'block_1': ''.join([hex(ord(i)).replace('0x', '').zfill(2) for i in raw_block_1])})
        if self.is_acquirer_present(blocks['term_id']):
            key = self.get_key_from_db(blocks['term_id'], 'TDK')
            if key:
                if blocks['descriptor'][6:] == '04':
                    cypher = DES3.new(unhexlify(key), mode=DES3.MODE_ECB)
                    full_key = DES3.new(
                        unhexlify(''.join([cypher.encrypt(unhexlify(blocks['block_1'])).hex(), blocks['block_2']])),
                        mode=DES3.MODE_CBC, IV=unhexlify(blocks['block_2'])
                    )
                    result = full_key.decrypt(
                        data[18 + int(blocks['descriptor'][2:4], 16):]
                    ).rsplit(b'\x80', maxsplit=1)[0]

                    length = self.convert_string_to_bytes(hex(len(result)).replace('0x', '').zfill(4))
                    return b''.join([length, result])
                else:
                    self.console_print(f"Unknown decoder scheme №{blocks['descriptor'][6:]}!", level='ERROR')
                    self.write_in_log(f"Unknown decoder scheme №{blocks['descriptor'][6:]}!", level='ERROR')
            else:
                self.console_print(f"There's no TDK key in database for Terminal ID = '{blocks['term_id']}'!", level='ERROR')
                self.write_in_log(f"There's no TDK key in database for Terminal ID = '{blocks['term_id']}'!", level='ERROR')
                self.console_print(f"At first you should download keys in terminal.", level='WARNING')
        else:
            self.console_print(f"There's no Terminal ID = '{blocks['term_id']}' in 'acquirer_data' table!", level='ERROR')
            self.write_in_log(f"There's no Terminal ID = '{blocks['term_id']}' in 'acquirer_data' table!", level='ERROR')
        return None

    def convert_string_to_bytes(self, text):
        self.conv_res = list()
        text = text.zfill(len(text) + len(text) % 2)
        for i in range(len(text) // 2):
            self.conv_res.append(int(text[i * 2:i * 2 + 2], 16))
        return bytes(self.conv_res)

    @staticmethod
    def get_timestamp(predef_datetime=None):
        if predef_datetime:
            t = predef_datetime - timedelta(hours=3)
        else:
            t = datetime.now() - timedelta(hours=3)

        timestamp = ''.join([
            str(t.year).zfill(4),
            str(t.month).zfill(2),
            str(t.day).zfill(2),
            str(t.hour).zfill(2),
            str(t.minute).zfill(2),
            str(t.second).zfill(2),
            str(t.microsecond)[:2]
        ])
        return timestamp

    @staticmethod
    def xor(first, second):
        return hex(int(first, 16) ^ int(second, 16)).replace('0x', '').zfill(8)


class OWNResponseGenerator(DbManger):
    def __init__(self, emulator, init=True):
        if init: super().__init__()
        self.emulator = emulator
        self.conv_res = list()
        self.tag_list = list()
        self.request = dict()
        self.mac_flag = False
        self.tdk = None
        self.rrn = None
        self.f_list = None
        self.mac_key = None
        self.response = None
        self.key_pack = None
        self.clear_req = None
        self.predefined_rc = None
        self.response_code = None
        self.operation_name = None
        self.resp_message_type = None

    def get_response(self, request, clear_req):
        self.__init__(self.emulator, init=False)
        self.clear_req = clear_req
        self.request = request
        try:
            assert self.get_tag_list(), 'list of tags generation'

            if self.operation_name == 'KEY_LOAD':
                self.tdk = self.get_key_from_db(self.request['Field <41>'], 'TDK') if 'Field <41>' in self.request else None
                self.mac_key = self.get_key_from_db(self.request['Field <41>'], 'TAK') if 'Field <41>' in self.request else None
                try: self.key_load_solver(self.request['Field <48>'], self.request['Field <41>'])
                except KeyError: raise AssertionError('key generation')
            else:
                if 'Field <64>' in self.request:
                    if self.calculate_mac(mode='request') != self.request['Field <64>']:
                        self.predefined_rc = b'88'

            assert self.get_fields(), 'tags generation'
            assert self.compile(), 'bitmap generation'

            self.write_trans_data()
            return self.response, self.tdk
        except AssertionError as e:
            self.write_in_log(f'Error appeared in process of {e}', level='ERROR')
            self.console_print(f'Error appeared in process of {e}', level='ERROR')
            return None

    def compile(self):
        bitmap = self.get_bitmap()
        body = b''.join([self.resp_message_type, bitmap, b''.join(self.f_list)])
        if self.mac_flag:
            body = b''.join([body, self.convert_string_to_bytes(self.calculate_mac(data=body))])
        length = self.convert_string_to_bytes(hex(len(body)).replace('0x', '').zfill(4))
        self.response = b''.join([length, body])
        return True

    def get_fields(self):
        result, no_tag = list(), list()
        for tag in self.tag_list:
            value = self.get_tag(tag)

            if value: result.append(value)
            else:
                if not (tag == '64' and self.mac_flag):
                    self.write_in_log(f"Can't generate field with tag <{tag}>", level='WARNING')
                    self.console_print(f"Can't generate field with tag <{tag}>", level='WARNING')
                    no_tag.append(tag)
        self.tag_list = [field_tag for field_tag in self.tag_list if field_tag not in no_tag]
        self.f_list = result
        return True

    def get_tag(self, tag):
        if tag == '02':
            tmp = self.request['Field <2>'] if 'Field <2>' in self.request else None
            if tmp: res = b''.join([self.convert_string_to_bytes(str(len(tmp))), self.convert_string_to_bytes(tmp)])
            else: res = None
        elif tag == '03':
            tmp = self.request['Field <3>'] if 'Field <3>' in self.request else None
            if tmp: res = self.convert_string_to_bytes(tmp)
            else: res = None
        elif tag == '04':
            tmp = self.request['Field <4>'] if 'Field <4>' in self.request else None
            if tmp: res = self.convert_string_to_bytes(tmp)
            else: res = None
        elif tag == '07':
            t = datetime.now()
            tmp = ''.join([str(t.month).zfill(2), str(t.day).zfill(2), str(t.hour).zfill(2),
                           str(t.minute).zfill(2), str(t.second).zfill(2)])
            res = self.convert_string_to_bytes(tmp)
        elif tag == '11':
            tmp = self.request['Field <11>'] if 'Field <11>' in self.request else None
            res = self.convert_string_to_bytes(tmp)
        elif tag == '12':
            t = datetime.now()
            tmp = ''.join([str(t.hour).zfill(2), str(t.minute).zfill(2), str(t.second).zfill(2)])
            res = self.convert_string_to_bytes(tmp)
        elif tag == '13':
            t = datetime.now()
            tmp = ''.join([str(t.month).zfill(2), str(t.day).zfill(2)])
            res = self.convert_string_to_bytes(tmp)
        elif tag == '24':
            tmp = self.request['Field <24>'] if 'Field <24>' in self.request else None
            res = self.convert_string_to_bytes(tmp)
        elif tag == '37':
            tmp = self.get_rrn()
            res = tmp.encode('utf-8')
            self.rrn = tmp
        elif tag == '38':
            tmp = str(self.get_last_rowid() + 1).zfill(6)
            res = tmp.encode('utf-8')
        elif tag == '39':
            if self.predefined_rc:
                self.response_code = self.predefined_rc
                return self.predefined_rc

            if self.emulator:
                tmp = self.get_text_from_db('own_response_fields',
                                            'emulator_rc',
                                            ['op_name', self.operation_name])
                try: int(tmp)
                except ValueError: raise AssertionError('response code')
                assert len(tmp) == 2, 'response code'
                res = tmp.encode('utf-8')
            else:
                res = self.get_rc()
            self.response_code = res.decode('utf-8')
        elif tag == '41': res = self.request['Field <41>'].encode('utf-8') if 'Field <41>' in self.request else None
        elif tag == '48': res = self.key_pack if self.key_pack else None
        elif tag == '49': res = b'\x06\x43'                                                             # WRONG METHOD
        elif tag == '60': res = b'\x00\x06000307'                                                       # WRONG METHOD
        elif tag == '61':
            if self.operation_name == 'ALI_QR':
                res = b'\x00\x00\x26\xeb\x18\xf2\x16\xc2\x14\x54https://example.com'
            else: res = None
        elif tag == '63':
            tmp = self.request['Field <63>'] if 'Field <63>' in self.request else None
            if tmp: res = b''.join([self.convert_string_to_bytes(str(len(tmp)).zfill(4)), tmp.encode('utf-8')])
            else: res = None
        elif tag == '64':
            if 'Field <41>' not in self.request: return None
            if self.is_acquirer_present(self.request['Field <41>']):
                if self.get_key_from_db(self.request['Field <41>'], 'TAK'):
                    self.mac_flag = True
            return None
        else: return None

        return res

    def get_rc(self):
        return b'00'                                                                                    # WRONG METHOD

    def get_tag_list(self):
        self.tag_list = list()
        self.operation_name = self.get_operation_name()
        if not self.operation_name: return False
        fields = self.get_text_from_db('own_response_fields',
                                       'value',
                                       ['op_name', self.operation_name])

        if fields:
            tmp = fields.split('|')[0].split(';')
            self.tag_list = [i.zfill(2) for i in tmp if len(i) <= 2]
            if 'Field <64>' in self.request: self.tag_list.append('64')
            return True
        else: return False

    def get_operation_name(self):
        self.resp_message_type = None
        m_type = self.request['Message type']
        p_code = self.request['Field <3>'] if 'Field <3>' in self.request else None
        if m_type == '0100':
            if p_code == '000000':
                self.resp_message_type = b'\x01\x10'
                return 'AUTH_NEW'
        elif m_type == '0200':
            if p_code == '000000':
                self.resp_message_type = b'\x02\x10'
                return 'SALE'
            elif p_code in ['200000', '250000']:
                self.resp_message_type = b'\x02\x10'
                return 'REFUND'
        elif m_type == '0220':
            if 'Field <24>' not in self.request: return None
            additional_data = self.request['Field <63>'] if 'Field <63>' in self.request else ''
            if self.request['Field <24>'] == '0201':
                self.resp_message_type = b'\x02\x30'
                if 'Alipay' in additional_data:
                    return 'AUTH_FIN'
                else:
                    return 'FIN_ADVICE'
            elif self.request['Field <24>'] == '0202':
                if p_code == '000000':
                    self.resp_message_type = b'\x02\x30'
                    return 'AUTH_FIN'
        elif m_type == '0400':
            if p_code == '000000':
                self.resp_message_type = b'\x04\x10'
                return 'VOID'
        elif m_type in ['0420', '0421']:
            if p_code == '000000':
                self.resp_message_type = b'\x04\x30'
                return 'REVERSAL'
        elif m_type == '0620':
            self.resp_message_type = b'\x06\x30'
            return 'ALI_STATUS'
        elif m_type == '0800':
            if p_code == '930000':
                self.resp_message_type = b'\x08\x10'
                return 'HANDSHAKE'
            if p_code == '960000':
                self.resp_message_type = b'\x08\x10'
                return 'KEY_LOAD'
        elif m_type == '9420':
            if p_code == '380000':
                self.resp_message_type = b'\x94\x30'
                return 'QR_REVERSAL'
        elif m_type == '9700':
            if p_code == '380000':
                self.resp_message_type = b'\x97\x10'
                return 'ALI_QR'
        return None

    def key_load_solver(self, data, term_id):
        def gen_block(temp):
            tmp_dict = dict()
            temp = temp.split(b'\xdf')[1:]
            [tmp_dict.update({hex(i[0]).replace('0x', ''): i[2:].decode('utf-8')}) for i in temp]
            return tmp_dict

        packs = dict()
        if not self.is_acquirer_present(term_id):
            self.write_in_log(f"Terminal ID = '{term_id}' is not present in 'acquirer_data' table", level='WARNING')
            self.console_print(f"Terminal ID = '{term_id}' is not present in 'acquirer_data' table", level='WARNING')
            self.predefined_rc = b'01'
            return False
        key = self.get_key_from_db(term_id, 'KLK')
        data = unhexlify(data).split(b'\xff')[1:]
        if key:
            [packs.update({hex(block[0]).replace('0x', ''): gen_block(block)}) for block in data]
            for pack in packs:
                try:
                    if packs[pack]['24'] == 'KLK':
                        klk = DES3.new(unhexlify(key))
                        check_val = klk.encrypt(unhexlify('0' * 32)).hex().upper()[:6]
                        if packs[pack]['22'] == check_val:
                            index = self.get_klk_index(term_id)
                            if index == int(packs[pack]['20']) or index == 0:
                                key_field = self.get_key_pack(term_id, key, index)
                                self.key_pack = b''.join([self.convert_string_to_bytes(str(len(key_field))), key_field])
                                return True
                            else:
                                self.write_in_log(f"Wrong KLK index! (client-{str(int(packs[pack]['20']))}, host-{index})", level='WARNING')
                                self.console_print(f"Wrong KLK index! (client-{str(int(packs[pack]['20']))}, host-{index})", level='WARNING')
                        else:
                            self.write_in_log(f"Check value of KLK is not the same! (client-{packs[pack]['22']}, host-{check_val})", level='WARNING')
                            self.console_print(f"Check value of KLK is not the same! (client-{packs[pack]['22']}, host-{check_val})", level='WARNING')
                except KeyError:
                    self.write_in_log(f"Missing tag in block '{pack}' of field '41'!", level='ERROR')
                    self.console_print(f"Missing tag in block '{pack}' of field '41'!", level='ERROR')
        self.predefined_rc = b'01'
        return False

    def get_key_pack(self, term_id, key, index):
        if index != 0: index += 6
        key_list = ['KLK', 'MTAK', 'MTPK', 'MTDK', 'TAK', 'TPK', 'TDK']
        enc_sequence = {'KLK': 'KLK', 'MTAK': 'KLK', 'MTPK': 'KLK', 'MTDK': 'KLK',
                        'TAK': 'MTAK', 'TPK': 'MTPK', 'TDK': 'MTDK'}
        term_translate = {'KLK': 'KLK', 'MTAK': 'TAMK', 'MTPK': 'TPMK', 'MTDK': 'TMK',
                          'TAK': 'TAK', 'TPK': 'TPK', 'TDK': 'TDK'}
        self.gen_keys(term_id, mode='PSB')
        key_dict = dict()
        result = list()

        [key_dict.update({key_name: self.get_key_from_db(term_id, key_name)}) for key_name in key_list]
        for name in key_list:
            crypto_key = DES3.new(unhexlify(key_dict[name]), DES3.MODE_ECB)
            curr_key_index = str(index + key_list.index(name) + 1).encode('utf-8')
            if name == 'KLK':
                enc_key = DES3.new(unhexlify(key), DES3.MODE_ECB)
                DF25 = b'\xdf\x25\x02\x30\x30'
            else:
                enc_key = DES3.new(unhexlify(key_dict[enc_sequence[name]]), DES3.MODE_ECB)
                DF25 = b'\xdf\x25\x02\x30\x34'
            DF20 = b''.join([b'\xdf\x20', self.convert_string_to_bytes(hex(len(curr_key_index)).replace('0x', '')), curr_key_index])
            DF22 = b''.join([b'\xdf\x22\x06', crypto_key.encrypt(unhexlify('0' * 32)).hex().upper()[:6].encode('utf-8')])
            DF23 = b'\xdf\x23\x01\x54'
            DF24 = b''.join([b'\xdf\x24', self.convert_string_to_bytes(hex(len(term_translate[name])).replace('0x', '')), term_translate[name].encode('utf-8')])
            DF28 = b''.join([b'\xdf\x28', self.convert_string_to_bytes(hex(len(term_translate[enc_sequence[name]])).replace('0x', '')),
                             term_translate[enc_sequence[name]].encode('utf-8')])
            DF29 = b'\xdf\x29\x02\x30\x30'
            DF40 = b'\xdf\x40\x01\x31'
            DF41 = b''.join([b'\xdf\x41\x20', enc_key.encrypt(unhexlify(key_dict[name])).hex().upper().encode('utf-8')])

            res_list = [DF20, DF22, DF23, DF24, DF25, DF28, DF40, DF41]
            if name == 'KLK': res_list.append(DF29)
            result.append(b''.join([b'\xff', self.convert_string_to_bytes(str(key_list.index(name) + 1)),
                                    self.convert_string_to_bytes(hex(len(b''.join(res_list))).replace('0x', '')),
                                    b''.join(res_list)]))
        self.write_new_int_in_acq_data(term_id, index + 1, 'KLK_index')
        return b''.join(result)

    def get_rrn(self):
        rrn = ''.join([str(randint(0, 9)) for _ in range(12)])
        rrn_list = self.get_rrn_list()
        if rrn in rrn_list: return self.get_rrn()
        else: return rrn

    def calculate_mac(self, mode='response', data=None):
        def xor(first, second):
            return hex(int(first, 16) ^ int(second, 16)).replace('0x', '').zfill(16)

        raw_list = list()
        if self.mac_key: key = self.mac_key
        else: key = self.get_key_from_db(self.request['Field <41>'], 'TAK')

        if not key: return None
        left_part = DES.new(unhexlify(key[:16]), mode=DES.MODE_CBC, IV=unhexlify('0000000000000000'))
        full_key = DES3.new(unhexlify(key), mode=DES.MODE_CBC, IV=unhexlify('0000000000000000'))

        if mode == 'request':
            raw_data = self.clear_req[2:-4].hex()
        elif mode == 'response':
            raw_data = data.hex()
        else: return None

        [raw_list.append(raw_data[i * 16:(i + 1) * 16]) for i in range(len(raw_data) // 16 + 1)]
        while len(raw_list[-1]) != 16: raw_list[-1] += '0'
        if raw_list[-1] == '0000000000000000': raw_list.pop()
        dump = None
        for block in raw_list:
            del left_part
            left_part = DES.new(unhexlify(key[:16]), mode=DES.MODE_CBC, IV=unhexlify('0000000000000000'))

            if dump: tmp = xor(dump, block)
            else: tmp = block

            if raw_list.index(block) + 1 == len(raw_list): dump = full_key.encrypt(unhexlify(tmp)).hex()
            else: dump = left_part.encrypt(unhexlify(tmp)).hex()
        return dump.upper()[:8]

    def write_trans_data(self):
        ignore_list = ['HANDSHAKE', 'KEY_LOAD']
        if self.operation_name in ignore_list: return None

        t = datetime.now()
        date = '.'.join([str(t.day).zfill(2), str(t.month).zfill(2), str(t.year)[2:].zfill(2)])
        time = ':'.join([str(t.hour).zfill(2), str(t.minute).zfill(2), str(t.second)[:2].zfill(2)])
        columns = ['op_type', 'resp_code', 'date_time', 'acquirer_id', 'trans_is_real', 'closed', 'verified', 'void', 'voided', 'partial_void']
        data_dict = {
            'op_type': self.operation_name,
            'resp_code': self.response_code,
            'date_time': ' '.join([date, time]),
            'acquirer_id': self.request['Field <41>'] if 'Field <41>' in self.request else None,
            'value': int(self.request['Field <4>']) if 'Field <4>' in self.request else None,
            'trans_is_real': not self.emulator,
            'rrn': self.rrn if '37' in self.tag_list else None,
            'balance': int(self.request['Field <4>']) if 'Field <4>' in self.request else None,
            'reference': self.request['Field <37>'] if 'Field <37>' in self.request else None,
            'closed': False,
            'verified': False,
            'void': False,
            'partial_void': False,
            'voided': 0
        }
        additional = ['value', 'balance', 'rrn', 'reference']
        [columns.append(col) for col in additional if data_dict[col]]
        self.write_in_db('transaction_data',
                         tuple([data_dict[name] for name in columns]),
                         tuple(columns))

    def convert_string_to_bytes(self, text):
        self.conv_res = list()
        text = text.zfill(len(text) + len(text) % 2)
        for i in range(len(text) // 2):
            self.conv_res.append(int(text[i * 2:i * 2 + 2], 16))
        return bytes(self.conv_res)

    def get_bitmap(self):
        bitmap = list()
        bit_list = ['0' for _ in range(64)]
        for tag in self.tag_list:
            bit_list[int(tag) - 1] = '1'
        [bitmap.append(hex(int(''.join(bit_list[i*8:i*8+8]), 2)).replace('0x', '').zfill(2)) for i in range(8)]
        return self.convert_string_to_bytes(''.join(bitmap))


if __name__ == '__main__':
    tmp = b'\x00\\\n\x0c\x00\x04\xd30\r\xdf  \x04#\x13BWg12341234\x01\x0214.\\8b\xb6w3\x91\x8f\x8cI\x11)\x1c<-Ya\x1029f\x7f\x07WW\xf4\x85O\xad\xf7\x9e\xde!X\xe5g\x9e{%\xc4n\xaf\xac\x96p\x0b-v\xe4\xe7T:\xd0\'k\x05D"N3\xc7\xf1\x9f'
    cl = OWNEncryption()
    cl.decode(tmp)
