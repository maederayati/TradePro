
import logging

class Utils:

    def __init__(self):
        pass

    def get_logger(self, name = 'logger'):
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            level=logging.INFO,
            datefmt='%Y-%m-%d %H:%M:%S')
        return logging.getLogger(name)
