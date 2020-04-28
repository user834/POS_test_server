from binascii import unhexlify
from db_manager import DbManger
from Crypto.Cipher import DES3, DES
from datetime import datetime
from os import getcwd, path
from random import randint
from konfig import Config
import traceback
import re


class SettlementSolver(DbManger):
    def __init__(self):
        super().__init__()
        self.settle_dict = dict()
        self.resp_dict = dict()

    def parse_line(self, line):
        separator = re.findall(r'\d{4}[+-]\d{18}', line)
        self.settle_dict = {
            'shift': line[:3],
            'packet': line[3:6],
            'debit': [separator[0][:4], separator[0][4], separator[0][5:]],
            'credit': [separator[1][:4], separator[1][4], separator[1][5:]],
            'adjustment': [separator[2][:4], separator[2][4], separator[2][5:]]
        }

    def get_total(self, acquirer, mode, flag, total=0):
        voided_list = list()
        trans_list = list()
        if mode == 'debit': trans_list = self.get_debit_from_db(acquirer)
        elif mode == 'credit': trans_list = self.get_credit_from_db(acquirer)
        elif mode == 'adjustment': return '0000+000000000000000000'
        for trans in trans_list:
            if flag == 'm': self.write_new_verified_status(trans, True)

            if self.is_trans_voided: value = self.get_value_of_trans(trans) - self.get_single_int_from_db(trans, 'voided')
            else: value = self.get_value_of_trans(trans)

            if value: total += value
            else:
                if not self.is_trans_partial_voided(trans): voided_list.append(trans)
        [trans_list.pop() for _ in voided_list]
        return ''.join([str(len(trans_list)).zfill(4), '+' if total >= 0 else '-', str(abs(total)).zfill(18)])

    def compile_settlement(self, request):
        try:
            field = list()
            if 'Field <l>' in request: field = ['l', request['Field <l>']]
            elif 'Field <o>' in request: field = ['o', request['Field <o>']]
            elif 'Field <m>' in request: field = ['m', request['Field <m>']]
            self.parse_line(field[1])
            self.resp_dict = {
                'shift': str(int(self.settle_dict['shift']) + 1).zfill(3) if field[0] == 'o' else self.settle_dict['shift'],
                'packet': str(int(self.settle_dict['packet']) + 1).zfill(3) if field[0] == 'l' else self.settle_dict['packet'],
                'debit': self.get_total(request['Terminal ID'].rstrip(), 'debit', field[0]),
                'credit': self.get_total(request['Terminal ID'].rstrip(), 'credit', field[0]),
                'adjustment': '0000+000000000000000000'
            }
            return ''.join([self.resp_dict[s_part] for s_part in self.resp_dict])
        except Exception: print(traceback.format_exc())


class TptpResponseGenerator(SettlementSolver):
    """Solves response on tptp request"""
    def __init__(self, rc_dict, emulator=False, init=True):
        if init: super().__init__()
        self.trans_id = str()
        self.header = dict()
        self.request = None
        self.result = list()
        self.settings = dict()
        self.resp_fields = list()
        self.emulator = emulator
        self.rc_dict = rc_dict
        self.get_settings()
        self.fields_of_resp = dict()
        self.master_key = DES3.new(unhexlify('0123456789ABCDEFFEDCBA9876543210'), DES3.MODE_ECB)

    def get_response(self, request):
        """Main function, that starts response generation"""
        self.__init__(self.rc_dict, self.emulator, init=False)
        self.request = request
        self.fields_of_resp.clear()
        try:
            assert self.get_header(), 'header'
            assert self.get_other_fields(), 'tags'

            self.write_trans_data()
            return b'\x1c'.join(self.result)
        except AssertionError as e:
            self.write_in_log(f'Error appeared in process of {e} generation', level='ERROR')
            self.console_print(f'Error appeared in process of {e} generation', level='ERROR')
            return None

    def get_rc(self):
        if self.emulator:
            try:
                op_type = '-'.join([self.header[i] for i in ['Transaction code', 'Message type', 'Message sub type']])
                return self.rc_dict[op_type]
            except KeyError:
                self.console_print(f'Operation is not supplied.', level='ERROR')
                self.write_in_log(f'Operation is not supplied.', level='ERROR')
                return None
        else:
            rc = None
            date = self.request['Current date']
            amount = int(self.request['Field <B>']) if 'Field <B>' in self.request else None
            term_id = self.request['Terminal ID'].rstrip()
            trans_id = self.request['Field <t>'] if 'Field <t>' in self.request else None
            mac_val = self.request['Field <G>'] if 'Field <G>' in self.request else None
            try:
                if self.header['Message type'] == 'F':
                    assert self.is_acquirer_present(term_id), f'Terminal id = "{term_id}" is not present in database'
                    cash = self.get_amounts(term_id)
                    if mac_val and mac_val != self.calculate_mac(mode='request'): return '898'  # получен неверный МАС
                    if self.header['Message sub type'] == 'O':
                        if self.header['Transaction code'] == '00':
                            if cash[0] - cash[1] - amount >= 0:
                                self.write_new_amount(term_id, cash[0] - amount)
                                rc = '001'  # одобрено
                            else:
                                rc = '076'  # нехватка средств
                        elif self.header['Transaction code'] == '01':
                            if cash[0] - cash[1] - amount >= 0:
                                self.write_new_preauth_amount(term_id, cash[1] + amount)
                                rc = '001'  # одобрено
                            else:
                                rc = '076'  # нехватка средств
                        elif self.header['Transaction code'] == '02':
                            if self.get_op_type_by_trans_id(trans_id) != '01-F-O': return '055'  # некорректные атрибуты
                            if self.get_status_by_trans_id(trans_id): return '801'  # не найдена оригинальная операция
                            balance = self.get_balance_of_trans(trans_id)
                            if cash[1] >= balance and cash[0] - cash[1] >= 0:
                                self.write_new_preauth_amount(term_id, cash[1] - balance)
                                self.write_new_amount(term_id, cash[0] - amount)
                                self.write_new_status(trans_id, True)
                                self.write_new_balance(trans_id, 0)
                                rc = '001'  # одобрено
                            else:
                                self.write_in_log('Database is damaged!', level='ERROR')
                                self.console_print('Database is damaged! Go to src/data.db and delete it.', level='ERROR')
                                rc = '074'  # невозможно авторизовать
                        elif self.header['Transaction code'] == '04':
                            if trans_id:
                                if self.get_op_type_by_trans_id(trans_id) not in ['00-F-O', '02-F-O']: return '055'  # некорректные атрибуты
                                if self.get_status_by_trans_id(trans_id): return '801'  # не найдена оригинальная операция
                                balance = self.get_balance_of_trans(trans_id)
                                if balance:
                                    if amount <= balance:
                                        if balance - amount <= 0:
                                            self.write_new_status(trans_id, True)
                                        self.write_new_amount(term_id, cash[0] + amount)
                                        self.write_new_balance(trans_id, balance - amount)
                                        rc = '001'  # одобрено
                                    else: rc = '205'  # некорректная сумма
                                else: rc = '801'  # не найдена ориганильная операция
                            else:
                                self.write_new_amount(term_id, cash[0] + amount)
                                rc = '001'  # одобрено
                        elif self.header['Transaction code'] == '05':
                            commission = round(amount/100*5)
                            if cash[0] - cash[1] - amount - commission >= 0:
                                self.write_new_amount(term_id, cash[0] - amount - commission)
                                rc = '001'  # одобрено
                            else: rc = '076'  # нехватка средств
                        elif self.header['Transaction code'] == '07': rc = '001'  # одобрено
                        elif self.header['Transaction code'] == '14':
                            if self.get_op_type_by_trans_id(trans_id) != '01-F-O': return '055'  # некорректные атрибуты
                            if self.get_status_by_trans_id(trans_id): return '801'  # не найдена оригинальная операция
                            if cash[0] - cash[1] - amount >= 0:
                                self.write_new_balance(trans_id, self.get_balance_of_trans(trans_id) + amount)
                                self.write_new_preauth_amount(term_id, cash[1] + amount)
                                rc = '001'  # одобрено
                            else: rc = '076'  # нехватка средств
                        elif self.header['Transaction code'] == '35': rc = '001'  # одобрено
                        elif self.header['Transaction code'] == '36': rc = '001'                    # WRONG METHOD
                    elif self.header['Message sub type'] == 'U':
                        if self.get_op_type_by_trans_id(trans_id) == '-'.join([self.header['Transaction code'], self.header['Message type'], 'O']):
                            if not self.is_void_legal(date, trans_id): return '074'  # невозможно авторизоать
                            if self.get_status_by_trans_id(trans_id): return '801'  # не найдена оригинальная операция
                            self.write_new_bool_status(trans_id, True, 'void')

                            balance = self.get_balance_of_trans(trans_id)
                            if self.header['Transaction code'] in ['00', '02']:
                                voided = self.get_single_int_from_db(trans_id, 'voided')
                                value = self.get_value_of_trans(trans_id)
                                rest = int(self.request['Field <X>']) if 'Field <X>' in self.request else None
                                if self.get_original_auth_code(trans_id) != self.request['Field <F>']: return '055'  # некорректные атрибуты
                                if rest:
                                    self.write_new_bool_status(trans_id, True, 'partial_void')
                                    self.write_new_int_in_tran_data(trans_id, voided + value - rest, 'voided')
                                    self.write_new_amount(term_id, cash[0] + value - rest)
                                    self.write_new_balance(trans_id, balance - value + rest)
                                    if balance - value + rest <= 0: self.write_new_status(trans_id, True)
                                    rc = '001'  # одобрено
                                else:
                                    self.write_new_int_in_tran_data(trans_id, voided + balance, 'voided')
                                    self.write_new_status(trans_id, True)
                                    self.write_new_amount(term_id, cash[0] + balance)
                                    self.write_new_balance(trans_id, 0)
                                    rc = '001'  # одобрено
                            elif self.header['Transaction code'] in ['01']:
                                self.write_new_preauth_amount(term_id, cash[1] - balance)
                                self.write_new_balance(trans_id, 0)
                                self.write_new_status(trans_id, True)
                                rc = '001'  # одобрено
                            elif self.header['Transaction code'] in ['04']:
                                voided = self.get_single_int_from_db(trans_id, 'voided')
                                self.write_new_int_in_tran_data(trans_id, voided + balance, 'voided')
                                self.write_new_status(trans_id, True)
                                self.write_new_balance(trans_id, 0)
                                self.write_new_amount(term_id, cash[0] - balance)
                                rc = '001'
                            elif self.header['Transaction code'] in ['14']:
                                reference = self.get_reference_of_trans(trans_id)
                                ref_balance = self.get_balance_of_trans(reference)
                                self.write_new_status(trans_id, True)
                                self.write_new_balance(trans_id, 0)
                                self.write_new_balance(reference, ref_balance - balance)
                                self.write_new_preauth_amount(term_id, cash[1] - balance)
                                rc = '001'  # одобрено
                        else: rc = '801'  # не найдена оригинальная операция
                    elif self.header['Message sub type'] == 'T': rc = '001'  # одобрено
                elif self.header['Message type'] == 'A':
                    if self.header['Message sub type'] == 'O':
                        if self.header['Transaction code'] == '90':
                            if not self.is_acquirer_present(term_id):
                                self.console_print(f"Can't process! No Terminal ID with name '{term_id}' in database!", level='ERROR')
                                self.write_in_log(f"Can't process! No Terminal ID with name '{term_id}' in database!", level='ERROR')
                                return None
                            if self.request['Field <V>'][3] == 'h':
                                if self.gen_keys(term_id): rc = '880'  # одобрено
                                else: return None
                            else: rc = '880'  # одобрено
                        elif self.header['Transaction code'] in ['60', '61', '62']:
                            rc = '007'  # сверка одобрена
                        elif self.header['Transaction code'] == '95':
                            if mac_val and mac_val != self.calculate_mac(mode='request'): return '898'  # получен неверный МАС
                            rc = '001'  # одобрено
            except AssertionError as e:
                self.write_in_log(e, level='ERROR')
                self.console_print(e, level='ERROR')
                rc = '074'  # невозможно авторизовать
            except KeyError:
                self.write_in_log(traceback.format_exc(), level='ERROR')
                rc = None
            return rc

    def get_trans_id(self):
        trans_list = self.get_trans_id_list()
        if self.header['Message sub type'] == 'U':
            trans_id = self.request['Field <t>'] if 'Field <t>' in self.request else None
            if trans_id:
                try:
                    if not self.request['Field <F>'] == self.get_original_auth_code(self.request['Field <t>']):
                        self.write_in_log("Authorization code from request doesn't match with database value!", level='ERROR')
                        self.console_print("Authorization code from request doesn't match with database value!", level='ERROR')
                        return None
                except KeyError:
                    self.write_in_log('No authorization code in request!', level='ERROR')
                    self.console_print('No authorization code in request!', level='ERROR')
                    return None
        else:
            trans_id = ''.join([str(randint(0, 9)) for _ in range(8)])
            if trans_id in trans_list: return self.get_trans_id()
        return trans_id

    def get_header(self):
        try:
            self.header = dict()
            for name in self.request:
                self.header.update({name: self.request[name]})
                if name == 'Response code': break

            self.header['Current date'] = ''.join(str(datetime.now().date()).split('-'))[2:]
            self.header['Current time'] = ''.join(str(datetime.now().time()).split('.')[0].split(':'))
            self.header['Response code'] = self.get_rc()

            if not self.header['Response code']: return False
            self.result.append(b''.join([self.header[f_name].encode('utf-8') for f_name in self.header]))
            return True
        except Exception:
            self.write_in_log(traceback.format_exc(), level='ERROR')
            return False

    def get_other_fields(self):
        def get_field(tag):
            def g_tag():
                if 'Field <6>' not in self.request:
                    if self.request['Transaction code'] == '01': return '<QR:https://example.com>'
                    elif self.request['Transaction code'] == '36': return '<ALIPAY_STATUS:SUCCESS>'     # WRONG METHOD!!!
                else: return None

            def a_tag():
                def get_subs(subtag):
                    try:
                        if subtag == 'C': return self.request['Sub field <C>']
                        elif subtag == 'R': return '01'                                                 # WRONG METHOD!!!
                        elif subtag == 'r': return self.trans_id
                        elif subtag == 'p': return self.trans_id
                        elif subtag == 'W': return '1 '                                                 # WRONG METHOD!!!
                        elif subtag == 'F': return str(round(int(self.request['Field <B>'])/100*5)) if 'Field <B>' in self.request else None
                        else: raise KeyError
                    except KeyError:
                        self.write_in_log(f"Can't generate sub field <{subtag}> in field <a>", level='WARNING')
                        self.console_print(f"Can't generate sub field <{subtag}> in field <a>", level='WARNING')
                        return None

                res = [''.join(['&', t, get_subs(t), '#']) for t in re.findall(r'a\[(.*)\]', self.settings[op_name].split('|')[1])[0].split(',') if get_subs(t)]
                return ''.join(res)

            def J_tag():
                if self.emulator: return '       12345678900'
                else: return str(self.get_amounts(self.request['Terminal ID'].rstrip())[0]).rjust(18)

            def W_tag():
                if 'Field <V>' in self.request:
                    if self.request['Field <V>'][3] == 'h':  # TAK
                        key = self.get_key_from_db(self.request['Terminal ID'].rstrip(), 'TAK')
                        res = self.master_key.encrypt(unhexlify(key)).hex().upper()
                        return ''.join(['0\x1dh ', res])
                    elif self.request['Field <V>'][3] == 'g':  # TPK
                        key = self.get_key_from_db(self.request['Terminal ID'].rstrip(), 'TPK')
                        res = self.master_key.encrypt(unhexlify(key)).hex().upper()
                        return ''.join(['0\x1dg ', res])
                else: return None

            try:
                if tag == 'F': return ''.join([str(self.get_last_rowid() + 1).zfill(6), ' A'])
                elif tag == 'R': return self.request['Field <R>']
                elif tag == 'g': return g_tag()
                elif tag == 'h': return ''.join([self.request['Field <h>'][:-1], '0'])
                elif tag == 't': return self.trans_id
                elif tag == 'a': return a_tag()                                                             # WRONG METHOD!!!
                elif tag == 'J': return J_tag()
                elif tag == 'V': return self.request['Field <V>'] if 'Field <V>' in self.request else None
                elif tag == 'W': return W_tag()
                elif tag == 'G': return self.calculate_mac(mode='response')
                elif tag == 'S': return self.request['Field <S>'] if 'Field <S>' in self.request else None  # WRONG METHOD!!!
                elif tag in ['l', 'o', 'm']: return self.compile_settlement(self.request)
                else: return None
            except Exception:
                return None

        op_name = '-'.join([self.request['Transaction code'],
                            self.request['Message type'],
                            self.request['Message sub type']])
        try: tags = self.settings[op_name].split('|')[0].split(';')
        except KeyError:
            self.console_print(f'Operation is not supplied.', level='ERROR')
            self.write_in_log(f'Operation is not supplied.', level='ERROR')
            return False

        self.resp_fields = list()
        self.trans_id = self.get_trans_id()
        if not self.trans_id: return False
        if 'Field <G>' in self.request or op_name == '90-A-O': tags.append('G')

        if op_name == '60-A-O': tags.append('l')
        elif op_name == '61-A-O': tags.append('o')
        elif op_name == '62-A-O': tags.append('m')
        for field_tag in tags:
            if field_tag:
                field = get_field(field_tag)
                if field:
                    self.fields_of_resp.update({f'Field <{field_tag}>': field})
                    self.resp_fields.append(''.join([field_tag, field]))
                else:
                    self.console_print(f"Can't generate field with tag <{field_tag}>", level='WARNING')
                    self.write_in_log(f"Can't generate field with tag <{field_tag}>", level='WARNING')
        self.result.extend([i.encode('utf-8') for i in self.resp_fields])
        return True

    def write_trans_data(self):
        columns = ['op_type', 'resp_code', 'date_time', 'acquirer_id', 'trans_is_real', 'closed', 'verified', 'void', 'voided', 'partial_void']
        data_dict = {
            'op_type': '-'.join([self.header[i] for i in ['Transaction code', 'Message type', 'Message sub type']]),
            'resp_code': self.header['Response code'],
            'date_time': ' '.join(['.'.join([self.header['Current date'][6-i*2:8-i*2] for i in range(1, 4)]),
                                   ':'.join([self.header['Current time'][i*2:i*2+2] for i in range(3)])]),
            'acquirer_id': self.header['Terminal ID'].rstrip(),
            'value': self.request['Field <B>'] if 'Field <B>' in self.request else None,
            'trans_is_real': not self.emulator,
            'trans_id': self.trans_id if not self.request['Message sub type'] == 'U' else None,
            'balance': self.request['Field <B>'] if 'Field <B>' in self.request else None,
            'reference': self.request['Field <t>'] if 'Field <t>' in self.request else None,
            'closed': False,
            'verified': False,
            'void': False,
            'partial_void': False,
            'voided': 0
        }
        additional = ['value', 'balance', 'trans_id', 'reference']
        [columns.append(col) for col in additional if data_dict[col]]
        if data_dict['op_type'] not in ['60-A-O', '61-A-O', '62-A-O']:
            self.write_in_db('transaction_data',
                             tuple([data_dict[name] for name in columns]),
                             tuple(columns))

    def calculate_mac(self, mode=''):
        def xor(first, second):
            return hex(int(first, 16) ^ int(second, 16)).replace('0x', '').zfill(16)

        def get_hex(data):
            res = list()
            [res.append(hex(ord(i)).replace('0x', '').zfill(2)) for i in data]
            return ''.join(res)

        key = self.get_key_from_db(self.request['Terminal ID'].rstrip(), 'TAK')
        if not key: return None
        left_part = DES.new(unhexlify(key[:16]), mode=DES.MODE_CBC, IV=unhexlify('0000000000000000'))
        full_key = DES3.new(unhexlify(key), mode=DES.MODE_CBC, IV=unhexlify('0000000000000000'))
        raw_list = list()

        if mode == 'response':
            t_list = list()
            f_list = ['Transmission number', 'Terminal ID', 'Transaction code']
            if self.header['Response code'] != '   ': f_list.append('Response code')
            [t_list.append(f'Field <{tag}>') for tag in ['B', 'S', 'q'] if f'Field <{tag}>' in self.fields_of_resp]
            raw_data = ''.join([''.join([self.header[name] for name in f_list]),
                                ''.join([self.fields_of_resp[tag] for tag in t_list])])
            [raw_list.append(get_hex(raw_data[i * 8:(i + 1) * 8])) for i in range(len(raw_data) // 8 + 1)]
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
        elif mode == 'request':
            f_list = ['Transmission number', 'Terminal ID', 'Transaction code']
            if self.request['Response code'] != '   ': f_list.append('Response code')
            [f_list.append(f'Field <{tag}>') for tag in ['B', 'S', 'q'] if f'Field <{tag}>' in self.request]
            raw_data = ''.join([self.request[name] for name in f_list])
            [raw_list.append(get_hex(raw_data[i*8:(i+1)*8])) for i in range(len(raw_data)//8 + 1)]
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
        else: return None

    def get_settings(self):
        """Converts config settings into python dict()"""
        config = Config(path.join(getcwd(), 'src', 'config.ini')).as_args()
        [self.settings.update({config[i * 2][2:]: config[i * 2 + 1]}) for i in range(len(config) // 2)]
