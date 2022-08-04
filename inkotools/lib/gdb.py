#!/usr/bin/env python3
# lib/gdb.py

# internal imports
import html
import logging
import re
from datetime import datetime
from zoneinfo import ZoneInfo

# external imports
import mechanicalsoup

# local imports

# module logger
log = logging.getLogger(__name__)


class GRAYDB:
    """Class for interacting with the gray database"""

    def __init__(self, url, credentials):
        """Init of graydb class

        url: string         - base url to database

        credentials: dict {
            login: str      - user name
            password: str   - password
        }
        """
        self.browser = mechanicalsoup.StatefulBrowser(
            raise_on_404=True,
            user_agent='inkotools-api/0.4',
        )
        self.baseurl = url
        self.credentials = credentials
        self._login()

    def __del__(self):
        self.browser.close()

    class CredentialsError(Exception):
        """Custom exception on wrong creds"""

        def __init__(self, msg="Wrong login or password!"):
            self.message = msg
            super().__init__(self.message)

    class NotFoundError(Exception):
        """Custom exception for not found errors"""

        def __init__(self, msg="Client not found"):
            self.message = msg
            super().__init__(self.message)

    def _login(self):
        """Login to graydb"""
        b = self.browser
        b.open(self.baseurl)
        # check that there is the auth form
        if len(b.page.select('form[name=auth]')) > 0:
            b.select_form('form[name=auth]')
            b['username'] = self.credentials['login'].encode('cp1251')
            b['password'] = self.credentials['password'].encode('cp1251')
            b.submit_selected()
            # check if auth form again - wrong login
            if len(b.page.select('form[name=auth]')) > 0:
                raise self.CredentialsError()
            else:
                log.debug('Logged in successfully')
        else:
            log.debug('Already logged in')

    def _check_auth(func):
        """Check auth decorator"""

        def wrapper(self, *args, **kwargs):
            self._login()
            return func(self, *args, **kwargs)
        return wrapper

    def get_client_ip_list(self, contract_id: str):
        """Get list of client ips from billing"""
        inet = self.get_billing_accounts(contract_id)['internet']
        if len(inet) == 0:
            raise self.NotFoundError('Internet account not found')
        return inet['ip_list']

    def get_billing_accounts(self, contract_id: str):
        """Get list of client services from billing"""
        raw = self.browser.post(f'{self.baseurl}/bil.php',
                                data={"nome_dogo": contract_id})
        account_types = [
            "internet",
            "telephony",
            "ld_telephony",
            "television",
        ]
        # init res dict with empty accounts
        res = dict.fromkeys(account_types, {})
        # iterate through all accounts (first row is table header)
        for idx, row in enumerate(raw.soup.select('table tr')[1:]):
            item = {}
            item['account_id'] = int(row.contents[0].string)
            item['services'] = list(map(gdb_decode, row.contents[1].strings))
            # remove `,` and `;` symbols and split without empty strings
            ip_tel = row.contents[3].string.translate(
                {ord(i): None for i in ';,'}).split()
            # internet
            if idx == 0:
                item['tariff'] = gdb_decode(row.contents[2].string)
                item['ip_list'] = ip_tel
            # telephony
            elif idx < 3:
                item['number_list'] = ip_tel
            item['balance'] = float(row.contents[5].string)
            item['credit'] = float(row.contents[7].string)
            status = gdb_decode(row.contents[8].string)
            item['enabled'] = True if status == 'Разблокирован' else False
            res[account_types[idx]] = item

        return res

    def get_billing_speed(self, ip: str):
        """Get billing speed for ip address"""
        ip = str(ip)
        raw = self.browser.get(f'http://62.182.48.36/speed/index.php?ip1={ip}')
        raw = raw.soup.get_text().strip()
        rgx = r'esteblished= (\d+ Mbit/sec)'
        r = re.findall(rgx, raw)
        if len(r) == 0:
            res = "error"
            log.error(raw)
        else:
            res = r[0]
        return res

    def get_billing_summary(self, contract_id: str):
        """Get billing accounts with billing speed included"""
        res = self.get_billing_accounts(contract_id)
        if len(res['internet']['ip_list']) > 0:
            # speed is the same for all ips, so, select first
            res['internet']['speed'] = self.get_billing_speed(
                res['internet']['ip_list'][0])
        return res

    def get_contract_by_ip(self, client_ip: str):
        """Find contract with client ip"""
        client_ip = str(client_ip)
        raw = self.browser.post(f'{self.baseurl}/poisk_test.php',
                                data={"ip": client_ip, "go99": 1})
        # graydb has fuzzy search, so iterate through several contracts
        # and check if contract's ip is the searched ip
        for row in raw.soup.select('tbody tr'):
            contract_id = row.find('td').string.strip()
            if client_ip in self.get_client_ip_list(contract_id):
                return contract_id

        raise self.NotFoundError()

    def get_internal_client_id(self, contract_id: str):
        """Get internal client id in gray database"""
        raw = self.browser.post(f'{self.baseurl}/poisk_test.php',
                                data={"dogovor": contract_id, "startt": 1})
        f = raw.soup.find('input', {'name': 'id_aabon'})
        if f is None:
            raise self.NotFoundError()
        res = int(f.get('value'))
        return res

    @_check_auth
    def get_client_data(self, contract_id: str):
        """Get client info from gray database"""
        client_id = self.get_internal_client_id(contract_id)
        raw = self.browser.get(f'{self.baseurl}/index.php',
                               params={"id_aabon": client_id})
        raw = raw.soup
        res = {'contract_id': contract_id, 'client_id': client_id}
        # matching dict between returning keys and form input names
        m_dict = {
            'name': 'fio',
            'company': 'organizatsiya',
            'house': 'dom',
            'room': 'kvartira',
            'office': 'ofis_tseh',
            'sw_ip': 'loyalnost',
            'port': 'port',
            'cable_length': 'dlina_cab',
        }
        # select form with client data (form with input `fio`)
        d = list(raw.find('input', {'name': 'fio'}).parents)[6]
        # iterate through the form inputs
        for key, val in m_dict.items():
            res[key] = d.find(attrs={'name': val}).get('value').strip()
        # get city and street from first (selected) option in select
        m_dict = {
            'city': 'gorod',
            'street': 'ulitsa',
        }
        for key, val in m_dict.items():
            res[key] = d.find(
                'select', {'name': val}).option.get('value').strip()
        # generate contact list
        res['contact_list'] = []
        for i in range(1, 4):
            c = d.find(attrs={'name': f'cont{i}'}).get('value').strip()
            # skip empty strings and legacy values
            if c in ['', '0']:
                continue
            # ignore duplicates
            if c not in res['contact_list']:
                res['contact_list'].append(c)
        # comment string from textarea
        res['comment'] = d.find(attrs={'name': 'primechanie'}).string
        res['comment'] = res['comment'].strip(
        ) if res['comment'] is not None else ''
        # search for terminated mark
        res['terminated'] = bool(
            raw.find('font', {'color': 'red', 'size': '2px'}))
        # clear legacy values from old db
        for i in res:
            if res[i] == '0':
                res[i] = ''
        # search for tickets
        tickets = []
        keys = ['ticket_id', 'issue', 'date', 'master', 'creator', 'comments']
        for t in raw.find_all(attrs={'name': 'id_start_zay'}):
            # get columns as reverted previous siblings of current
            cols = t.parent.find_previous_siblings()[4::-1]
            # generate values from td tags without last (comments)
            values = [x.string.split(':', 1)[1].strip() for x in cols[:-1]]
            # split comments (last column)
            comments = parse_comments(cols[-1])
            # join ticket_id and other values
            values = [int(t['value']), *values, comments]
            ticket = dict(zip(keys, values))
            # convert date from string to date
            ticket['date'] = datetime.strptime(
                ticket['date'], '%d-%m-%y').replace(
                tzinfo=ZoneInfo('Europe/Moscow'))
            # raw comments for add_comment
            ticket['raw_comments'] = t.parent.find(
                attrs={"name": "id_start_stadya"})["value"]
            tickets.append(ticket)
        res['tickets'] = tickets
        return res

    @_check_auth
    def get_tickets(self):
        """Get list of user tickets"""
        tickets = []
        keys = ['ticket_id', 'contract_id', 'name', 'issue', 'address',
                'contacts', 'date', 'creator']
        raw = self.browser.get(f'{self.baseurl}/zayavki.php')
        raw = raw.soup
        for row in raw.tbody.find_all('tr'):
            values = list(map(lambda x: re.sub(
                r' +', ' ', gdb_decode(x.text).strip()), row.find_all('td')))
            # normal user tickets
            if len(values) == 11:
                values = values[0:8]
            # boss tickets
            elif len(values) == 13:
                values = values[1:9]
            # error
            else:
                self.log.error(f'Wrong ticket structure: {values}')
                continue
            ticket = dict(zip(keys, values))
            # strip '№ ' from ticket id and convert to int
            ticket['ticket_id'] = int(ticket['ticket_id'][2:])
            # convert contacts to list and remove duplicates
            ticket['contacts'] = list(set(ticket['contacts'].split()))
            # convert str to date
            ticket['date'] = datetime.strptime(
                ticket['date'], '%d-%m-%y').replace(
                tzinfo=ZoneInfo('Europe/Moscow'))
            # add comments
            ticket['comments'] = parse_comments(row)
            tickets.append(ticket)
        return tickets

    @_check_auth
    def add_comment(self, contract_id: str, ticket_id: int, comment: str):
        """Add comment to ticket"""
        ticket_found = False
        client = self.get_client_data(contract_id)
        # ticket validation and getting old comments
        # in graydb we need to add all the old comments with the new one
        for i in client["tickets"]:
            if i["ticket_id"] == ticket_id:
                ticket_found = True
                old_comments = i["raw_comments"]
                break
        if not ticket_found:
            raise self.NotFoundError('Ticket not found')
        comment = html.escape(comment)
        data = {"tekst_zay": comment.encode("cp1251"),
                "id_start_zay": ticket_id,
                "id_start_stadya": old_comments.encode("cp1251"),
                }
        user = self.credentials['login']
        log.debug(f'[{user}] contract {contract_id}, ticket {ticket_id}, '
                  f'comment: {comment}')
        res = self.browser.post(f'{self.baseurl}/index.php', data=data)
        if res.ok:
            log.info(f'[{user}] commented [{contract_id}]')
            return 'Comment added successfully'
        else:
            log.error(f'[{user}] failed to comment [{contract_id}]')
            return {'error': 'Failed to add comment'}

    @_check_auth
    def search_ticket(self, contract_id: str, keywords: list = [],
                      search_in_comments: bool = False,
                      master: str = ''):
        """Search ticket by keywords"""
        res = []
        client = self.get_client_data(contract_id)
        kw = r'(?i)' + r'|'.join(keywords)
        for ticket in client['tickets']:
            if ((master == '' or ticket['master'] == master)
                and (re.search(kw, ticket['issue'])
                     or (search_in_comments
                         and re.search(kw, ticket['raw_comments'])))):
                res.append(ticket)
        return res

    @_check_auth
    def change_client_data(self, contract_id: str, data: dict):
        """Change client data in gray database

        Possible data: sw_ip, port, cable_length

        Returns: bool"""
        m_dict = {
            'sw_ip': 'loyalnost',
            'port': 'port',
            'cable_length': 'dlina_cab',
        }
        client_id = self.get_internal_client_id(contract_id)
        # get old user data from gray database
        raw = self.browser.get(f'{self.baseurl}/index.php',
                               params={"id_aabon": client_id})
        raw = raw.soup
        form = list(raw.find('input', {'name': 'fio'}).parents)[6]
        fields = form.find_all(['input', 'select', 'textarea'])
        old_data = {}
        for item in fields:
            if (not 'name' in item.attrs
                    or item.attrs['name'] in ['zayavka', 'otvetstv']):
                # skip submit button and ticket inputs
                continue
            key = item.attrs['name']
            if item.name == 'input':
                val = item.attrs['value'].encode("cp1251")
            elif item.name == 'textarea':
                val = item.text.encode("cp1251")
            elif item.name == 'select':
                val = item.option.get('value').encode("cp1251")
            old_data[key] = val
        # update data with provided values
        new_data = old_data
        for k, v in data.items():
            if k in m_dict:
                new_data[m_dict[k]] = v
        # send data to gray database
        raw = self.browser.post(f'{self.baseurl}/index.php', data=new_data)
        res = list(raw.soup.stripped_strings)[-1] == 'Завершено успешно!'
        if res:
            log.debug(f'[{contract_id}] data changed: {data}')
        else:
            log.error(f'[{contract_id}] failed to change data: {data}')
        return res

    @_check_auth
    def terminate_contract(self, contract_id: str):
        """Terminate contract in gray database"""
        # check for services in billing
        for k, v in self.get_billing_accounts(contract_id).items():
            if 'services' in v.keys() and len(v['services']) > 0:
                log.warning(
                    f'Found services in {k} billing account, aborting.')
                return False
        # send termination request
        self.browser.get(f'{self.baseurl}/index.php',
                         params={"rastorg": contract_id})
        return True


########################################################################
# common functions


def parse_comments(tag):
    """Search for comments within soup tag"""
    comments = []
    for i, e in enumerate(tag.find_all(href='#')):
        comments.append({
            "time": datetime.strptime(
                e['title'], '%d.%m.%Y %H:%M:%S').replace(
                tzinfo=ZoneInfo('Europe/Moscow')),
            "author": gdb_decode(e.string),
            "comment": list(map(
                gdb_decode, e.parent.strings))[(i+1)*2].strip()[2:-1],
        })
    return comments


def gdb_decode(s):
    try:
        res = s.encode('ISO-8859-1').decode('cp1251')
    except Exception:
        res = s
    return res
