
import csv
from TradePro.Ameritrade import Ameritrade

class Symbol:

    def __init__(self, sector, ticker):
        self.ticker = ticker
        self.sector = sector


    @staticmethod
    def get_sp500():
        res = []
        with open("SP500_Companies_basics.csv", newline='') as csvfile:
            rows = csv.reader(csvfile, delimiter=',')
            rows.__next__()
            for row in rows:
                sector = row[2]
                symbol = row[0]
                res.append(Symbol(sector, symbol))
        return res

    @staticmethod
    def get_watchlist(a: Ameritrade = None):
        if a is None:
            a = Ameritrade()
            a.authorize()

        wls = a.get_watchlists()
        symbols = []
        for wl in wls:
            sector = wl['name']
            for item in wl['watchlistItems']:
                symbols.append(Symbol(sector=sector, ticker=item['instrument']['symbol']))
        return symbols


if __name__ == "__main__":
    from pprint import pprint
    pprint([i.__dict__ for i in Symbol.get_watchlist()])