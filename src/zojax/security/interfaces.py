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
""" zojax.security interfaces

$Id$
"""
from zope import interface
from zope.i18nmessageid import MessageFactory

_ = MessageFactory('zojax.security')


class IZojaxSecurityPolicy(interface.Interface):
    """ zojax security policy """


class IPrincipalGroups(interface.Interface):
    """ principal groups """

    principal = interface.Attribute('Principal')

    def getGroups(type=None):
        """ get principal groups """


class IExtendedGrantInfo(interface.Interface):
    """ similar to IGrantInfo but recursive """

    def getRolesForPermission(permission):
        """ roles with permission """

    def getRolesForPrincipal(principal):
        """ principal roles """

    def getPrincipalsForRole(role_id):
        """ Get the principals that have been granted a role. """

    def getPrincipalsForPermission(permission):
        """ Get principals for permission """


class IPublicRole(interface.Interface):
    """ public role """


class IManagerRole(interface.Interface):
    """ marker interface for manager role """


class IPublicPermission(interface.Interface):
    """ marker interface for allowed permissins """


class IPermissionCategory(interface.Interface):
    """ permissions category """


class IPermissionCategoryType(interface.interfaces.IInterface):
    """Permission category type"""
