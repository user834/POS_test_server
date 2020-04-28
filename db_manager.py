from integrity import Logger
from random import randint
import traceback
import sqlite3
import os
import re


class DbManger(Logger):
    def __init__(self):
        super().__init__()
        self.conn = sqlite3.connect(os.path.join(os.getcwd(), 'src', 'data.db'))
        self.cursor = self.conn.cursor()
        self.command = str()

    def gen_keys(self, acquirer, mode='MK'):
        if mode == 'MK': key_list = ['TAK', 'TPK']
        elif mode == 'PSB': key_list = ['KLK', 'MTAK', 'MTPK', 'MTDK', 'TAK', 'TPK', 'TDK']
        else: return False
        for key in key_list:
            key_val = ''.join([hex(randint(0, 15)).replace('0x', '').upper() for _ in range(32)])
            self.cursor.execute(f"UPDATE acquirer_data SET {key}='{key_val}' WHERE card_acceptor_terminal='{acquirer}'")
        self.conn.commit()
        return True

    def get_debit_from_db(self, acquirer):
        self.cursor.execute(f"SELECT trans_id FROM transaction_data WHERE op_type IN ('00-F-O', '05-F-O', '02-F-O') AND "
                            f"resp_code = '001' AND acquirer_id = '{acquirer}' AND verified = '0' AND trans_is_real = '1'")
        return [trans_id[0] for trans_id in self.cursor.fetchall()]

    def get_credit_from_db(self, acquirer):
        self.cursor.execute(f"SELECT trans_id FROM transaction_data WHERE op_type IN ('04-F-O') AND "
                            f"resp_code = '001' AND acquirer_id = '{acquirer}' AND verified = '0' AND trans_is_real = '1'")
        return [trans_id[0] for trans_id in self.cursor.fetchall()]

    def get_klk_index(self, acquirer):
        try:
            self.cursor.execute(f"SELECT KLK_index FROM acquirer_data WHERE card_acceptor_terminal='{acquirer}'")
            result = self.cursor.fetchone()[0]
            if result: return result
            else: return 0
        except TypeError: return 0

    def get_key_from_db(self, acquirer, key):
        try:
            self.cursor.execute(f"SELECT {key} FROM acquirer_data WHERE card_acceptor_terminal='{acquirer}'")
            return self.cursor.fetchone()[0]
        except TypeError: return None

    def get_trans_id_list(self):
        self.cursor.execute('SELECT trans_id FROM transaction_data')
        return [trans_id[0] for trans_id in self.cursor.fetchall()]

    def get_rrn_list(self):
        self.cursor.execute('SELECT rrn FROM transaction_data')
        return [trans_id[0] for trans_id in self.cursor.fetchall()]

    def get_status_by_trans_id(self, trans_id):
        self.cursor.execute(f"SELECT closed FROM transaction_data WHERE trans_id='{trans_id}'")
        return self.cursor.fetchone()[0]

    def get_original_auth_code(self, trans_id):
        self.cursor.execute(f"SELECT auth_code FROM transaction_data WHERE trans_id='{trans_id}'")
        return ''.join([str(self.cursor.fetchone()[0]).zfill(6), ' A'])

    def get_op_type_by_trans_id(self, trans_id):
        try:
            self.cursor.execute(f"SELECT op_type FROM transaction_data WHERE trans_id='{trans_id}'")
            return self.cursor.fetchone()[0]
        except TypeError: return None

    def get_reference_of_trans(self, trans_id):
        try:
            self.cursor.execute(f"SELECT reference FROM transaction_data WHERE trans_id='{trans_id}'")
            return self.cursor.fetchone()[0]
        except TypeError: return None

    def get_single_int_from_db(self, trans_id, column):
        try:
            self.cursor.execute(f"SELECT {column} FROM transaction_data WHERE trans_id='{trans_id}'")
            return self.cursor.fetchone()[0]
        except TypeError: return None

    def get_balance_of_trans(self, trans_id):
        try:
            self.cursor.execute(f"SELECT balance FROM transaction_data WHERE trans_id='{trans_id}'")
            return self.cursor.fetchone()[0]
        except TypeError:
            self.console_print(f"No transaction in database with trans_id='{trans_id}'", level='ERROR')
            return None

    def get_value_of_trans(self, trans_id):
        try:
            self.cursor.execute(f"SELECT value FROM transaction_data WHERE trans_id='{trans_id}'")
            return self.cursor.fetchone()[0]
        except TypeError:
            self.console_print(f"No transaction in database with trans_id='{trans_id}'", level='ERROR')
            return None

    def get_last_rowid(self):
        try:
            self.cursor.execute('SELECT rowid from transaction_data order by ROWID DESC limit 1')
            return self.cursor.fetchone()[0]
        except TypeError: return 0

    def get_value_from_ignore_list(self, op_name):
        try:
            self.cursor.execute("SELECT value FROM tptp_ignore_list WHERE op_name = 'GENERAL'")
            val = self.cursor.fetchone()[0]
            if val == 0:
                self.cursor.execute(f"SELECT value FROM tptp_ignore_list WHERE op_name = '{op_name}'")
                return self.cursor.fetchone()[0]
            else: return val
        except TypeError: return 0

    def get_text_from_db(self, table, element, statement):
        try:
            self.cursor.execute(f"SELECT {element} FROM {table} WHERE {statement[0]} = '{statement[1]}'")
            return self.cursor.fetchone()[0]
        except TypeError: return None

    def get_amounts(self, acquirer):
        self.cursor.execute(f"SELECT amount, preauth_amount FROM acquirer_data WHERE card_acceptor_terminal='{acquirer}'")
        return self.cursor.fetchall()[0]

    def get_server_option(self, option):
        try:
            self.cursor.execute(f"SELECT value FROM server_settings WHERE option='{option}'")
            result = self.cursor.fetchone()[0]
            if option == 'SERVER_IP':
                assert re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', result)
            elif option == 'SERVER_PORT':
                assert re.match(r'\d{1,5}', result)
                result = int(result)
                assert result in range(65536)
            elif option == 'PROTOCOL':
                result = result.upper()
                assert result in ['OWN', 'TPTP']
            elif option in ['EMULATOR_MODE', 'PRINT_PARSED', 'OWN_ENCRYPTION']:
                assert result in ['0', '1']
                result = bool(int(result))
            return result
        except AssertionError:
            self.console_print(f"Wrong value in 'server_settings' table with option = '{option}'!", level='ERROR')
            self.write_in_log(f"Wrong value in 'server_settings' table with option = '{option}'!", level='ERROR')
            return None
        except TypeError: return None

    def is_void_legal(self, date, trans_id):
        try:
            date = '.'.join([date[6-i*2:8-i*2] for i in range(1, 4)])
            self.cursor.execute(f"SELECT date_time FROM transaction_data WHERE trans_id='{trans_id}'")
            if self.cursor.fetchone()[0].split(' ')[0] == date: return True
            else: return False
        except TypeError: return False

    def is_acquirer_present(self, acquirer):
        self.cursor.execute(f'SELECT card_acceptor_terminal FROM acquirer_data')
        acquirer_list = [acq[0] for acq in self.cursor.fetchall()]
        return True if acquirer in acquirer_list else False

    def is_trans_voided(self, trans_id):
        self.cursor.execute(f"SELECT void FROM transaction_data WHERE trans_id='{trans_id}'")
        return True if self.cursor.fetchone()[0] == 1 else False

    def is_trans_partial_voided(self, trans_id):
        self.cursor.execute(f"SELECT partial_void FROM transaction_data WHERE trans_id='{trans_id}'")
        return True if self.cursor.fetchone()[0] == 1 else False

    def write_new_bool_status(self, trans_id, status, column, table='transaction_data'):
        self.cursor.execute(f"UPDATE {table} SET {column}={status} WHERE trans_id='{trans_id}'")
        self.conn.commit()

    def write_new_verified_status(self, trans_id, status):
        self.cursor.execute(f"UPDATE transaction_data SET verified={status} WHERE trans_id='{trans_id}'")
        self.conn.commit()

    def write_new_status(self, trans_id, status):
        self.cursor.execute(f"UPDATE transaction_data SET closed={status} WHERE trans_id='{trans_id}'")
        self.conn.commit()

    def write_new_preauth_amount(self, acquirer, amount):
        self.cursor.execute(f"UPDATE acquirer_data SET preauth_amount={str(amount)} WHERE card_acceptor_terminal='{acquirer}'")
        self.conn.commit()

    def write_new_amount(self, acquirer, amount):
        self.cursor.execute(f"UPDATE acquirer_data SET amount={str(amount)} WHERE card_acceptor_terminal='{acquirer}'")
        self.conn.commit()

    def write_new_balance(self, trans_id, val):
        self.cursor.execute(f"UPDATE transaction_data SET balance={str(val)} WHERE trans_id='{trans_id}'")
        self.conn.commit()

    def write_new_int_in_tran_data(self, trans_id, val, column):
        self.cursor.execute(f"UPDATE transaction_data SET {column}={str(val)} WHERE trans_id='{trans_id}'")
        self.conn.commit()

    def write_new_int_in_acq_data(self, term_id, val, column):
        self.cursor.execute(f"UPDATE acquirer_data SET {column}={str(val)} WHERE card_acceptor_terminal='{term_id}'")
        self.conn.commit()

    def write_in_db(self, table, values, columns=None):
        val_mask = ''.join(['(', ', '.join(['?' for _ in range(len(values))]), ')'])
        self.command = str()

        if columns:
            if len(columns) == len(values):
                column_str = str(columns).replace("\'", "")
                self.command = f'INSERT INTO {table} {column_str} VALUES {val_mask}'
            else:
                self.write_in_log(f'DB MANAGER> Number of values is not equal to number of columns\nVAL={values}\nCOL={columns}', level='ERROR')
                self.console_print('DB MANAGER> Number of values is not equal to number of columns', level='ERROR')
        else: self.command = f'INSERT INTO {table} VALUES {val_mask}'

        if self.command:
            try:
                self.write_in_log(f'DB COMMAND> {self.command}; values={str(values)}')
                self.cursor.execute(self.command, values)
                self.conn.commit()
            except sqlite3.IntegrityError as e:
                self.write_in_log(f'DB MANAGER> IntegrityError - {e}', level='ERROR')
                self.console_print(f'DB MANAGER> IntegrityError - {e}', level='ERROR')
            except sqlite3.OperationalError as e:
                self.write_in_log(f'DB MANAGER> OperationalError - {e}', level='ERROR')
                self.console_print(f'DB MANAGER> OperationalError - {e}', level='ERROR')
        else:
            self.write_in_log('DB MANAGER> No command to execute!', level='ERROR')
            self.console_print('DB MANAGER> No command to execute!', level='ERROR')


if __name__ == '__main__':
    cl = DbManger()
    cl.get_server_option('SERVER_IP')
