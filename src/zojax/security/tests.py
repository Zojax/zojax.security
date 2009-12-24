##############################################################################
#
# Copyright (c) 2007 Zope Corporation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
""" zojax.security tests

$Id$
"""
__docformat__ = "reStructuredText"

import unittest, doctest
from zope import interface, schema
from zope.app.testing import setup, ztapi
from zope.security.management import endInteraction
from zope.securitypolicy.tests import test_zopepolicy
from zojax.security.grantinfo import ExtendedGrantInfo
from zojax.security.interfaces import IExtendedGrantInfo


def setUp(test):
    test_zopepolicy.setUp(test)
    ztapi.provideAdapter(
        interface.Interface, IExtendedGrantInfo, ExtendedGrantInfo)

def tearDown(test):
    setup.placelessTearDown()


def test_suite():
    return unittest.TestSuite((
            doctest.DocFileSuite(
                'grantinfo.txt', setUp=setUp, tearDown=tearDown),
            doctest.DocFileSuite(
                'securitypolicy.txt',setUp=setUp, tearDown=tearDown),
            doctest.DocFileSuite(
                'zcml.txt', setUp=setUp, tearDown=tearDown,
                optionflags=doctest.NORMALIZE_WHITESPACE|doctest.ELLIPSIS),
            doctest.DocTestSuite(
                'zojax.security.vocabulary',
                setUp=setup.placelessSetUp, tearDown=setup.placelessTearDown, 
                optionflags=doctest.NORMALIZE_WHITESPACE|doctest.ELLIPSIS),
            ))
