#!/bin/env python3

import logging
import Util

class ContextConflictsError(Exception):
    pass

class MeshContext:
    def __init__(self, netkeys=[], appkeys=[], devicekeys=[]):
        self._netkeys = netkeys
        self._appkeys = appkeys
        self._devicekeys = devicekeys

    @property
    def netkeys(self):
        return self._netkeys

    @property
    def appkeys(self):
        return self._appkeys

    def __enter__(self):
        if len(self._netkeys) == 0:
            logging.warning('Enter Mesh Context with 0 netkeys')
        if len(self._appkeys) == 0:
            logging.warning('Enter Mesh Context with 0 appkeys')
        logging.debug('Enter Mesh Context')
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        logging.debug('Exit Mesh Context')

if __name__ == "__main__":
    with MeshContext():
        pass