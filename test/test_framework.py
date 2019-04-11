#!/usr/bin/env python

""" Passing and failing Test Cases to verify framework edits """

import unittest

from framework import VppTestCase, VppTestRunner


class TestFrameworkPassExplicit(VppTestCase):
    """ Pass using explicit calls to superclass methods """

    @classmethod
    def setUpClass(cls):
        super(TestFrameworkPassExplicit, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestFrameworkPassExplicit, cls).tearDownClass()

    def setUp(self):
        super(TestFrameworkPassExplicit, self).setUp()

    def tearDown(self):
        super(TestFrameworkPassExplicit, self).tearDown()

    def test_pass_explicit(self):
        pass


class TestFrameworkFailExplicit(VppTestCase):
    """ Fail using explicit calls to superclass methods """

    @classmethod
    def setUpClass(cls):
        super(TestFrameworkFailExplicit, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestFrameworkFailExplicit, cls).tearDownClass()

    def setUp(self):
        super(TestFrameworkFailExplicit, self).setUp()

    def tearDown(self):
        super(TestFrameworkFailExplicit, self).tearDown()

    def test_fail_explicit(self):
        self.fail()


class TestFrameworkPassImplicit(VppTestCase):
    """ Pass using implicit calls to superclass methods """

    def test_pass_implicit(self):
        pass


class TestFrameworkFailImplicit(VppTestCase):
    """ Fail using implicit calls to superclass methods """

    def test_fail_implicit(self):
        self.fail()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
