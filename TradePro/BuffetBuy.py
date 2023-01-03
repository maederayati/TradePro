from __future__ import annotations
import os, json
from TradePro.Ameritrade import Ameritrade
from TradePro.Utils import dict_get, write_to_file
import csv
from TradePro.Symbol import Symbol


class BuffetBuyScore:
    def __init__(self, symbol: Symbol, is_buy: bool, score: float, pe: float, pb: float):
        self.symbol = symbol
        self.is_buy = is_buy
        self.score = score
        self.pe = pe
        self.pb = pb


class BuffetBuy:

    def __init__(self):
        self.a = Ameritrade()
        self.a.authorize()


    def buffet_buy_score(self, symbol: Symbol):
        data = self.a.get_symbol_fundamental_info(symbol.ticker)[0]
        fd = dict_get(dict_get(data, symbol.ticker), 'fundamental')
        pe = dict_get(fd, 'peRatio')
        pb = dict_get(fd, 'pbRatio')
        score = BuffetBuyScore(symbol=symbol, is_buy=False, score=float('inf'), pe=pe, pb=pb)
        if pe is not None and pb is not None and pe < 15.0 and pb < 1.5 and pe * pb != 0:
            score.is_buy = True
            score.score = pe * pb
        return score

    def create_buffet_buy_list(self, symbols: list[Symbol], filename ='sp500_buffet_buys.txt'):
        for symbol in symbols:
            score = self.buffet_buy_score(symbol)
            if score.is_buy:
                score_str = json.dumps((score.symbol.sector, score.symbol.ticker, score.score, score.pe, score.pb))
                write_to_file(score_str + "\n", filename, append=True)


if __name__ == "__main__":
    bb = BuffetBuy()

    # s&p 500
    # sp_symbols = Symbol.get_sp500()
    # bb.create_buffet_buy_list(sp_symbols, 'sp500_buffet_buys.txt')

    # wl symbols
    wl_symbols = Symbol.get_watchlist()
    bb.create_buffet_buy_list(wl_symbols, 'watchlists_buffet_buys.txt')


