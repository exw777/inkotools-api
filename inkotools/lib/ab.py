#!/usr/bin/env python3
# lib/ab.py

# internal imports
import logging

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
            user_agent='inkotools-api/0.2',
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

    def get_client_ip_list(self, contract_id: str):
        """Get list of client ips from billing"""
        inet = self.get_billing_accounts(contract_id)['internet']
        if len(inet) == 0:
            raise self.NotFoundError('Internet account not found')
        return inet['ip_list']

    def get_billing_accounts(self, contract_id: str):
        """Get list of client services from billing"""
        raw = self.browser.post(f'{self.baseurl}/bil.php',
                                data={"nome_dogo": contract_id, "go": 1})
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
            item['services'] = list(row.contents[1].strings)
            # remove `,` and `;` symbols and split without empty strings
            ip_tel = row.contents[3].string.translate(
                {ord(i): None for i in ';,'}).split()
            # internet
            if idx == 0:
                item['tariff'] = row.contents[2].string
                item['ip_list'] = ip_tel
            # telephony
            elif idx < 3:
                item['number_list'] = ip_tel
            item['balance'] = float(row.contents[5].string)
            item['credit'] = float(row.contents[7].string)
            status = row.contents[8].string
            item['enabled'] = True if status == "Разблокирован" else False
            res[account_types[idx]] = item

        return res

    def get_client_by_ip(self, client_ip: str):
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
