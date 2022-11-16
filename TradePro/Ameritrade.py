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
        self.client_id_without_domain = self.consumer_key
        self.client_id_with_domain = self.client_id_without_domain + '@AMER.OAUTHAP'
        self.account_id = os.environ.get('TD_ACCOUNT_ID')
        self.redirect_uri = "https://localhost:5000"
        self.oauth_url = "https://api.tdameritrade.com/v1/oauth2/token"
        self.logger = Utils().get_logger(self.__class__.__name__)

        self.access_token = None
        self.refresh_token = None

    def authorize(self):
        token = self.get_token_from_file()
        print(token)
        if self.token_valid(token):
            self.access_token = token['access_token']
            self.refresh_token = token['refresh_token']
            return

        self.logger.warning('Access token from file expired.')
        token = self.get_token_from_refresh_token(token)
        print(token)

        if self.token_valid(token):
            self.access_token = token['access_token']
            self.update_access_token_in_file(token)
            return

        self.logger.warning('Refresh token expired.')
        raise Exception(f'code expired. Please update code from web by '
                        f'entering this url:{self.get_access_code_url()}'
                        f' and update the file by calling update_access_token_with_code() function '
                        f'providing code from url.')

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
    def write_to_file(content, filename, append=False):
        write_command = 'w' if not append else 'a'

        if isinstance(content, dict) or isinstance(content, tuple):
            content = json.dumps(content)
        if isinstance(content, bytes):
            write_command = write_command + 'b'

        with open(filename, write_command) as f:
            f.write(content)

    def api_call(self, method, url, data=None, params=None, header=None, return_status_code=False):
        self.logger.info('api call: ' + url)
        if method == 'post':
            res = requests.post(url=url, data=data, params=params, headers=header)

        elif method == 'get':
            res = requests.get(url=url, data=data, params=params, headers=header)

        time.sleep(1)
        if return_status_code:
            return {'content': json.loads(res.content), 'status_code': res.status_code}

        if res.status_code != 200:
            self.logger.info({'error message': res.content})
            raise Exception('Api call failed.')

        return json.loads(res.content)

    def get_access_code_url(self):
        return f"""
        https://auth.tdameritrade.com/auth?response_type=code&redirect_uri=https%3A%2F%2Flocalhost%3A5000&client_id={self.client_id_without_domain}%40AMER.OAUTHAP
        """

    def token_valid(self, token):
        if 'access_token' not in token:
            return False

        url = 'https://api.tdameritrade.com/v1/accounts/' + self.account_id
        res = self.api_call(method='get', url=url, header={'Authorization': 'Bearer ' + token['access_token']},
                            return_status_code=True)
        if res['status_code'] == 200:
            return True
        return False

    def update_code(self):
        raise NotImplemented

    def update_access_token(self, code):
        data = {
            'grant_type': 'authorization_code',
            'refresh_token': '',
            'access_type': 'offline',
            'code': self.decode(code),
            'client_id': self.client_id_with_domain,
            'redirect_uri': self.redirect_uri,
        }
        res = self.api_call(method='post', url=self.oauth_url, data=data, return_status_code=True)
        if res['status_code'] == 200:
            self.write_str_to_file(json.dumps(res['content']), 'config')
        else:
            raise Exception('Failed to get access token')

    def update_access_token_in_file(self, token):
        old_token = self.get_token_from_file()
        old_token['access_token'] = token['access_token']
        self.write_to_file(json.dumps(old_token), './config')

    def get_token_from_refresh_token(self, token):
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': token['refresh_token'],
            'access_type': '',
            'code': '',
            'client_id': self.client_id_with_domain,
            'redirect_uri': self.redirect_uri,
        }
        res = self.api_call(method='post', url=self.oauth_url, data=data, return_status_code=True)
        if res['status_code'] == 200:

            return res['content']
        else:
            self.logger.info('Cannot refresh code')

    def get_token_from_file(self, filename='./config'):
        f = open(filename, 'r')
        s = f.read()
        token = json.loads(s) if s != '' else {}
        f.close()
        return token

    def get_auth_header(self):
        return {'Authorization': 'Bearer ' + self.access_token}

    def get_symbol_cusip(self, symbol):

        url = "https://api.tdameritrade.com/v1/instruments/" + symbol
        data = {'apikey': self.consumer_key}
        res = self.api_call(method='get', url=url, params=data, header=self.get_auth_header())
        return res[0]['cusip']

    def get_symbol_fundamental_info(self, symbol):
        url = 'https://api.tdameritrade.com/v1/instruments'
        data = {'apikey': self.consumer_key,
                'symbol': symbol,
                'projection': 'fundamental'}
        res = self.api_call(method='get', url=url, params=data, header=self.get_auth_header())
        return res

    def get_watchlist_symbols(self):
        url = 'https://api.tdameritrade.com/v1/accounts/{}/watchlists'.format(self.account_id)
        res = self.api_call(method='get', url=url, header=self.get_auth_header())
        d = {wl['name']: [x['instrument']['symbol'] for x in wl['watchlistItems']] for wl in res}
        return d

    @staticmethod
    def dict_get(d, key):
        return None if d is None else d[key] if key in d else None

    def buffet_buy_score(self, symbol):
        data = self.get_symbol_fundamental_info(symbol)

        fd = self.dict_get(self.dict_get(data, symbol), 'fundamental')
        pe = self.dict_get(fd, 'peRatio')
        pb = self.dict_get(fd, 'pbRatio')
        res = dict(is_buy=False, score=float('inf'), pe=pe, pb=pb)
        if pe is not None and pb is not None and pe < 15.0 and pb < 1.5 and pe*pb!=0:
            res['is_buy'] = True
            res['score'] = pe*pb
        return res




if __name__ == "__main__":
    c = Ameritrade()
    c.authorize()

    symbol = 'CSPR'
    # res = c.get_watchlist_symbols()
    # print(res)
    # print(c.get_symbol_fundamental_info(symbol))
    # print(c.buffet_buy_score(symbol))

    d = {}
    sectors = c.get_watchlist_symbols()

    filename = 'buffet_buys.txt'
    os.remove(filename)

    for sector, symbols in sectors.items():
        d[sector] = []
        for symbol in symbols:
            score = c.buffet_buy_score(symbol)
            if score['is_buy']:
                d[sector].append(score)
                c.write_to_file(json.dumps((sector,symbol, score))+"\n", filename, append=True)
                print(symbol, score)
    # c.write_to_file(d, 'buffet_buys.txt', append=True)
