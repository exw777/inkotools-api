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
        pass

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
                raise self.CredentialsError('Wrong login or password!')
            else:
                log.debug('Logged in successfully')
        else:
            log.debug('Already logged in')

    def get_client_ip_list(self, contract_id: int):
        """Get list of client ips from billing"""
        raw = self.browser.post(f'{self.baseurl}/bil.php',
                                data={"nome_dogo": contract_id, "go": 1})
        try:
            # 2nd row - 1st account, 4th column - ip addresses
            res = raw.soup.table.contents[1].contents[3].string.strip('; ')
            if res == '':
                return {"error": "No ip address found", "status_code": 404}
            # split several ips to list
            res = res.split('; ')
            log.debug(f'[{contract_id}] {res}')
        except IndexError:
            log.error(f'Primary account not found')
            return {"error": "Primary account not found", "status_code": 404}
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
                return int(contract_id)
        return {"error": "Client not found", "status_code": 404}
