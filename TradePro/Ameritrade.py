import requests
import os
from urllib.parse import urlencode, quote_plus, unquote, quote
import json
import logging
import time
from pprint import pprint
from TradePro.Utils import Utils




class Ameritrade:

    def __init__(self):
        self.consumer_key = os.environ.get('TD_CONSUMER_KEY')
        self.client_id = self.consumer_key + '@AMER.OAUTHAP'
        self.account_id = os.environ.get('TD_ACCOUNT_ID')
        self.oauth_url = "https://api.tdameritrade.com/v1/oauth2/token"
        self.redirect_uri = "https://localhost:5000"

        self.logger = Utils().get_logger(self.__class__.__name__)

        self.read_token()
        if self.token_expired():
            self.logger.warning('Access token from file expired.')
            self.update_access_token_with_refresh_token()
            if self.token_expired():
                self.logger.warning('Refresh token expired.')
                raise Exception('code expired')

    @staticmethod
    def encode(s):
        return quote(s, safe='')

    @staticmethod
    def encode_json(payload):
        return urlencode(payload, quote_via=quote_plus)

    @staticmethod
    def decode(s):
        return unquote(s)

    @staticmethod
    def write_byte_to_file(b, filename):
        with open(filename, 'wb') as f:
            f.write(b)

    def api_call(self, method, url, data=None, params=None, header=None, return_status_code=False):
        self.logger.info('api call: ' + url)
        if method == 'post':
            res = requests.post(url=url, data=data, params=params, headers=header)

        if method == 'get':
            res = requests.get(url=url, data=data, params=params, headers=header)

        time.sleep(1)
        if return_status_code:
            return {'content': json.loads(res.content), 'status_code': res.status_code}

        if res.status_code != 200:
            self.logger.error({'error message': res.content})
            raise Exception('Api call failed.')

        return json.loads(res.content)

    def token_expired(self):
        return True if self.get_account_balance(return_status_code=True)['status_code'] != 200 else False

    def get_account_balance(self, return_status_code=False):
        url = 'https://api.tdameritrade.com/v1/accounts/' + self.account_id
        res = self.api_call(method='get', url=url, header={'Authorization': 'Bearer ' + self.access_token},
                            return_status_code=return_status_code)
        return res

    def update_code(self):
        raise NotImplemented

    def update_access_token_with_code(self, code):
        data = {
            'grant_type': 'authorization_code',
            'refresh_token': '',
            'access_type': 'offline',
            'code': self.decode(code),
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
        }
        res = self.api_call(method='post', url=self.oauth_url, data=data)

        with open('./config', 'wb') as f:
            f.write(res.content)
        self.read_token()

    def update_access_token_with_refresh_token(self):
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'access_type': '',
            'code': '',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
        }
        res = self.api_call(method='post', url=self.oauth_url, data=data, return_status_code=True)
        self.update_access_token(res['content']['access_token'])

    def update_access_token(self, access_token):
        self.access_token = access_token
        self.auth_header = {'Authorization': 'Bearer ' + access_token}

    def read_token(self):
        with open('./config', 'r') as f:
            s = f.read()
            token = json.loads(s)
            self.update_access_token(token['access_token'])
            self.refresh_token = token['refresh_token']

    def get_symbol_cusip(self, symbol):

        url = "https://api.tdameritrade.com/v1/instruments/" + symbol
        data = {'apikey': self.consumer_key}
        res = self.api_call(method='get', url=url, params=data, header=self.auth_header)
        return res[0]['cusip']

    def get_symbol_fundamental_info(self, symbol):
        url = 'https://api.tdameritrade.com/v1/instruments'
        data = {'apikey': self.consumer_key,
                'symbol': symbol,
                'projection': 'fundamental'}
        res = self.api_call(method='get', url=url, params=data, header=self.auth_header)
        return res

    def get_watchlist_symbols(self):
        url = 'https://api.tdameritrade.com/v1/accounts/{}/watchlists'.format(self.account_id)
        res = self.api_call(method='get', url=url, header=self.auth_header)
        d = {wl['name']: [x['instrument']['symbol'] for x in wl['watchlistItems']] for wl in res}
        return d


if __name__ == "__main__":
    c = Ameritrade()
    # symbol = 'SMCI'
    # c.get_symbol_cusip(symbol)
    # # print(c.get_symbol_fundamental_info(symbol))
    # # c.update_token()

    d = {}
    sectors = c.get_watchlist_symbols()

    for sector, symbols in sectors.items():
        d[sector] = []
        for symbol in symbols:
            temp = c.get_symbol_fundamental_info(symbol)
            pprint(temp)
            d[sector].append(temp)

    print(d)
    # c.update_access_token()
