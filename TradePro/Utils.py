
import logging
import json




class Utils:

    def __init__(self):
        pass

    @staticmethod
    def get_logger(name = 'logger'):
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            level=logging.INFO,
            datefmt='%Y-%m-%d %H:%M:%S')
        return logging.getLogger(name)

    @staticmethod
    def dict_get(d, key):
        return None if d is None else d[key] if key in d else None


    @staticmethod
    def write_to_file(content, filename, append=False):
        write_command = 'w' if not append else 'a'

        if isinstance(content, dict) or isinstance(content, tuple):
            content = json.dumps(content)
        if isinstance(content, bytes):
            write_command = write_command + 'b'

        with open(filename, write_command) as f:
            f.write(content)


dict_get = Utils.dict_get
write_to_file = Utils.write_to_file
get_logger = Utils.get_logger
