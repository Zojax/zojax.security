##############################################################################
#
# Copyright (c) 2009 Zope Foundation and Contributors.
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
"""

$Id$
"""
from zope import schema, interface, component
from zope.security.zcml import Permission
from zope.security.interfaces import IPermission
from zope.securitypolicy.interfaces import IRole
from zope.configuration.fields import GlobalInterface

from interfaces import IPublicRole, IManagerRole, IPublicPermission


class IPublicRoleDirective(interface.Interface):

    role = schema.Id(
        title=u"Role",
        description=u"Specifies the Role to be manageable.",
        required=True)

    manager = schema.Bool(
        title=u"Manager",
        description=u"Specifies the manager roles.",
        default=False,
        required=False)


class IPublicPermissionDirective(interface.Interface):

    permission = Permission(
        title = u'Permission',
        required = True)

    category = GlobalInterface(
        title = u'Category',
        description = u'Permission category',
        required = False)


def publicRoleHandler(_context, role, manager=False):
    _context.action(
	discriminator = ('zojax:role', role),
	callable = publicRole,
	args = (role, manager))


def publicRole(roleId, manager):
    sm = component.getSiteManager()

    role = sm.getUtility(IRole, roleId)
    
    if not manager:
        interface.directlyProvides(role, IPublicRole)
    else:
        interface.directlyProvides(role, IPublicRole, IManagerRole)

    sm.registerUtility(role, IPublicRole, roleId)


def publicPermissionHandler(_context, permission, category=None):
    if permission == 'zope.Public':
        raise TypeError('zope.Public permission is not allowed.')

    _context.action(
	discriminator = ('zojax:permission', permission),
	callable = publicPermission,
	args = (permission, category))


def publicPermission(name, category):
    sm = component.getSiteManager()

    permission = sm.getUtility(IPermission, name)

    interface.alsoProvides(permission, IPublicPermission)

    if category is not None:
        interface.alsoProvides(permission, category)

    sm.registerUtility(permission, IPublicPermission, name)
