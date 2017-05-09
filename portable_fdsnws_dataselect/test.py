# -*- coding: utf-8 -*-
"""
HTTP request handler
"""
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from future.builtins import *  # NOQA
import unittest
from portable_fdsnws_dataselect.request import DataselectRequest, QueryError
from portable_fdsnws_dataselect import version


class RequestTest(unittest.TestCase):
    def test_GET(self):
        request = DataselectRequest('/fdsnws/dataselect/%s/query?net=IU&start=2017-01-01&end=2017-01-02' % version[0])

        self.assertEqual(request.endpoint, 'query')
        self.assertListEqual(
            request.query_rows,
            [['IU', '*', '*', '*', '2017-01-01T00:00:00.000000', '2017-01-02T00:00:00.000000']]
        )

    def test_GET_multiples(self):
        request = DataselectRequest('/fdsnws/dataselect/%s/query?net=IU,II&sta=ANMO,CULA&start=2017-01-01&end=2017-01-02' % version[0])

        self.assertEqual(request.endpoint, 'query')
        self.assertEqual(len(request.query_rows), 4)

    def test_GET_missing_param(self):
        try:
            request = DataselectRequest('/fdsnws/dataselect/%s/query?net=IU' % version[0])
            self.fail('Expected QueryError')
        except QueryError:
            pass

    def test_GET_unknown_param(self):
        try:
            request = DataselectRequest('/fdsnws/dataselect/%s/query?net=IU&start=2017-01-01&end=2017-01-02&foo=bar' % version[0])
            self.fail('Expected QueryError')
        except QueryError:
            pass

    def test_GET_bad_date(self):
        try:
            request = DataselectRequest('/fdsnws/dataselect/%s/query?net=IU&start=201-01-01&end=2017-01-02' % version[0])
            self.fail('Expected QueryError')
        except QueryError:
            pass


if __name__ == '__main__':
    unittest.main()
