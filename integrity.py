from colorama import init, Fore, Style
from datetime import datetime
import traceback
import logging
import sqlite3
import socket
import os
import re


class Integrity(object):
    """Class for integrity check"""
    @staticmethod
    def is_src_present():
        if not os.path.exists(os.path.join(os.getcwd(), 'src')):
            os.mkdir(os.path.join(os.getcwd(), 'src'))
            return False
        else: return True

    @staticmethod
    def is_config_present():
        if not os.path.exists(os.path.join(os.getcwd(), 'src', 'config.ini')):
            file = open(os.path.join(os.getcwd(), 'src', 'config.ini'), 'w')
            file.write("""[00]
F-O=F;R;a;h;t|a[C,R,r,W,p]
F-U=F;a;t|a[R,r,p]
F-T=F;a;t|a[R,r,p]

[01]
F-O=F;R;a;g;h;t|a[C,R,r,p]
F-U=F;a;t|a[R,r,p]
F-T=F;a;t|a[R,r,p]

[02]
F-O=F;R;a;h;t|a[C,R,r,p]
F-U=F;a;t|a[R,r,p]
F-T=F;a;t|a[R,r,p]

[04]
F-O=F;a;h;t|a[C,R,r,p]
F-U=F;a;t|a[R,r,p]
F-T=F;a;t|a[R,r,p]

[05]
F-O=F;R;a;h;t|a[F,C,R,r,p,W]
F-T=F;a;t|a[R,r,p]

[07]
F-O=F;J;R;a;h;t|a[F,C,R,r,p,W]

[14]
F-O=F;a;h;t|a[C,R,r,p]
F-U=F;a;t|a[R,r,p]
F-T=F;a;t|a[R,r,p]

[35]
F-O=R;a;h|a[C,F]

[36]
F-O=F;a;g;h;t|a[C,R,r,p]

[60]
A-O=

[61]
A-O=

[62]
A-O=

[90]
A-O=V;W

[95]
A-O=""")
            file.close()
            return False
        else: return True

    @staticmethod
    def is_clue_present():
        if not os.path.exists(os.path.join(os.getcwd(), 'src', 'clue.txt')):
            file = open(os.path.join(os.getcwd(), 'src', 'clue.txt'), 'w')
            file.write("""00-F-O - оплата.
00-F-U - отмена(оплата).
00-F-T - реверс на отмену по ТО(Оплата).

01-F-O - преавторизация.
01-F-U - отмена преавторизации.
01-F-T - реверс на отмену по ТО(преавторизация).

02-F-O - расчет.
02-F-U - отмена(расчет).
02-F-T - реверс на отмену по ТО(расчет).

04-F-O - возврат.
04-F-U - отмена(возврат).
04-F-T - реверс на отмену по ТО(возврат).

05-F-O - выдача наличных(2-й этап).
05-F-T - реверс на отмену по ТО(выдача наличных(2-й этап)).

07-F-O - запрос баланса.

14-F-O - доавторизация.
14-F-U - отмена(доавторизация).
14-F-T - реверс на отмену по ТО(доавторизация).

35-F-O - выдача наличных.

36-F-O - запрос статуса Alipay.

60-A-O - сверка пакета.
61-A-O - сверка смены.
62-A-O - сверка дня.

90-A-O - загрузкак ключей.

95-A-O - тест связи.""")
            file.close()
            return False
        else: return True

    @staticmethod
    def is_srv_config_present():
        if not os.path.exists(os.path.join(os.getcwd(), 'src', 'srv_settings.ini')):
            file = open(os.path.join(os.getcwd(), 'src', 'srv_settings.ini'), 'w')
            file.write(f"""[Tptp_RC]
00-F-O=001
00-F-U=001
00-F-T=001

01-F-O=001
01-F-U=001
01-F-T=001

02-F-O=001
02-F-U=001
02-F-T=001

04-F-O=001
04-F-U=001
04-F-T=001

05-F-O=001
05-F-T=001

07-F-O=001

14-F-O=001
14-F-U=001
14-F-T=001

35-F-O=001

36-F-O=001

95-A-O=001""")
            file.close()
            return False
        else: return True

    @staticmethod
    def is_database_present():
        op_list = ['GENERAL', '00-F-O', '00-F-U', '00-F-T', '01-F-O', '01-F-U', '01-F-T', '02-F-O', '02-F-U', '02-F-T',
                   '04-F-O', '04-F-U', '04-F-T', '05-F-O', '05-F-T', '07-F-O', '14-F-O', '14-F-U', '14-F-T', '35-F-O',
                   '36-F-O', '60-A-O', '61-A-O', '62-A-O', '90-A-O', '95-A-O']
        own_field_ops = [['HANDSHAKE', '3;7;11;12;13;39;41;60;63;64'],
                         ['SALE', '2;3;4;7;11;12;13;37;38;39;41;49;63;64'],
                         ['REFUND', '2;3;4;7;11;12;13;37;38;39;41;49;63;64'],
                         ['VOID', '2;3;4;7;11;12;13;24;37;38;39;41;49;63;64'],
                         ['AUTH_NEW', '2;3;4;7;11;12;13;37;38;39;41;49;63;64'],
                         ['AUTH_FIN', '2;3;4;7;11;12;13;37;38;39;41;49;63;64'],
                         ['REVERSAL', '2;3;4;7;11;12;13;24;37;39;41;49'],
                         ['ALI_QR', '3;4;7;11;12;13;37;38;39;41;49;61;64'],
                         ['ALI_STATUS', '4;7;11;12;13;37;39;41;49'],
                         ['FIN_ADVICE', '2;3;7;11;37;39;41;49'],
                         ['QR_REVERSAL', '3;7;11;12;13;37;38;39;41;49'],
                         ['KEY_LOAD', '3;7;11;12;13;39;41;48']]
        server_settings = {
            'SERVER_IP': str(socket.gethostbyname_ex(socket.gethostname())[2][0]),
            'SERVER_PORT': '12345',
            'PROTOCOL': 'TPTP',
            'EMULATOR_MODE': '1',
            'PRINT_PARSED': '1',
            'OWN_ENCRYPTION': '1'
        }
        if not os.path.exists(os.path.join(os.getcwd(), 'src', 'data.db')):
            open(os.path.join(os.getcwd(), 'src', 'data.db'), 'w').close()
            conn = sqlite3.connect(os.path.join(os.getcwd(), 'src', 'data.db'))
            cursor = conn.cursor()
            cursor.execute("""CREATE TABLE transaction_data (
    auth_code     INTEGER  PRIMARY KEY,
    op_type       TEXT,
    rrn           TEXT,
    trans_id      TEXT,
    reference     TEXT,
    value         INTEGER,
    balance       INTEGER,
    voided        INTEGER  NOT NULL,
    resp_code     TEXT,
    date_time     DATETIME NOT NULL,
    acquirer_id   INTEGER  NOT NULL,
    trans_is_real BOOLEAN,
    closed        BOOLEAN  NOT NULL,
    verified      BOOLEAN  NOT NULL,
    void          BOOLEAN  NOT NULL,
    partial_void  BOOLEAN  NOT NULL
);""")
            conn.commit()
            cursor.execute("""CREATE TABLE acquirer_data (
    card_acceptor_terminal TEXT (16, 16)   PRIMARY KEY,
    amount                 INTEGER (1, 18) NOT NULL,
    preauth_amount         INTEGER         NOT NULL,
    TAK                    TEXT,
    TPK                    TEXT,
    TDK                    TEXT,
    KLK                    TEXT,
    MTAK                   TEXT,
    MTPK                   TEXT,
    MTDK                   TEXT,
    KLK_index              INTEGER
);""")
            conn.commit()
            cursor.execute("""CREATE TABLE tptp_ignore_list (
    op_name TEXT    PRIMARY KEY
                    NOT NULL
                    UNIQUE,
    value   INTEGER NOT NULL
);""")
            conn.commit()
            cursor.execute("""CREATE TABLE own_response_fields (
    op_name     TEXT UNIQUE
                     NOT NULL,
    value       TEXT,
    emulator_rc TEXT NOT NULL
);""")
            conn.commit()
            cursor.execute("""CREATE TABLE server_settings (
    option TEXT UNIQUE
                NOT NULL,
    value  TEXT
);""")
            for operation in op_list:
                cursor.execute('INSERT INTO tptp_ignore_list VALUES (?, ?)', (operation, 0))
            conn.commit()
            for data in own_field_ops:
                cursor.execute('INSERT INTO own_response_fields VALUES (?, ?, ?)', (data[0], data[1], '00'))
            conn.commit()
            for option in server_settings:
                cursor.execute('INSERT INTO server_settings VALUES (?, ?)', (option, server_settings[option]))
            conn.commit()
            return False
        else: return True

    @staticmethod
    def is_logs_present():
        if not os.path.exists(os.path.join(os.getcwd(), 'logs')):
            os.mkdir(os.path.join(os.getcwd(), 'logs'))
            return False
        else: return True

    @staticmethod
    def console_print(text, level='INFO', var=''):
        if level == 'ERROR': var = Fore.RED
        elif level == 'WARNING': var = Fore.YELLOW
        print(var + '[{:8}][{:^7}] {}'.format(str(datetime.now().time()).split(".")[0], level, text))

    def exam(self):
        try:
            assert Integrity.is_logs_present(), r'New directory "logs" created.'
            assert Integrity.is_src_present(), r'New directory "src" created.'
            assert Integrity.is_config_present(), r'New src\config.ini created.'
            assert Integrity.is_clue_present(), r'New src\clue.txt created.'
            assert Integrity.is_srv_config_present(), r'New src\srv_settings.ini created.'
            assert Integrity.is_database_present(), r'New src\data.db created.'
        except AssertionError as e:
            Integrity.console_print(e)
            self.exam()


class Logger(object):
    def __init__(self, filename=f'{str(datetime.now().date())}.log'):
        init(autoreset=True)  # Colorama init
        self.is_logs_full()
        self.text = str()
        self.message = str()
        self.log_list = list()
        self.filename = filename
        logging.basicConfig(filename=f'logs/{self.filename}',
                            filemode='a',
                            format=u'[%(filename)-18s][LINE:%(lineno)-4d][%(levelname)-8s][%(asctime)s] %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)

    def is_logs_full(self, maximal=10, path=os.path.join(os.getcwd(), 'logs')):
        self.log_list = list()
        [self.log_list.append(item) for item in os.listdir(path) if re.match(r'\d{4}-\d{2}-\d{2}\.log', item)]
        if len(self.log_list) > maximal:
            try: [os.remove(os.path.join(path, self.log_list.pop(0))) for _ in range(len(self.log_list)-maximal)]
            except PermissionError: self.write_in_log(traceback.format_exc())

    def write_in_log(self, message, level='INFO'):
        self.message = message
        if level == 'INFO': logging.info(self.message)
        elif level == 'WARNING': logging.warning(self.message)
        elif level == 'ERROR': logging.error(self.message)

    def console_print(self, text, level='INFO', var=''):
        self.text = text
        if level == 'ERROR': var = Fore.RED
        elif level == 'WARNING': var = Fore.YELLOW
        print(var + '[{:8}][{:^7}] {}'.format(str(datetime.now().time()).split(".")[0], level, self.text))
