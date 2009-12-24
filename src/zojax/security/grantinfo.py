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
""" IExtendedGrantInfo implmentation, extended version of IGrantInfo

$Id$
"""

from zope import interface, component
from zope.component import getAdapters
from zope.security.proxy import removeSecurityProxy
from zope.securitypolicy.interfaces import Unset

from zope.securitypolicy.interfaces import IPrincipalRoleMap
from zope.securitypolicy.interfaces import IRolePermissionMap
from zope.securitypolicy.interfaces import IPrincipalPermissionMap

from zope.securitypolicy.principalrole import principalRoleManager
globalPrincipalsForRole = principalRoleManager.getPrincipalsForRole

from zope.securitypolicy.principalpermission import principalPermissionManager
globalPrincipalPermission = principalPermissionManager.getPrincipalsForPermission

from interfaces import IExtendedGrantInfo
from securitypolicy import globalRolesForPrincipal, globalRolesForPermission


class ExtendedGrantInfo(object):
    component.adapts(interface.Interface)
    interface.implements(IExtendedGrantInfo)

    def __init__(self, context):
        self.context = context

    def getRolesForPermission(self, permission):
        context = removeSecurityProxy(self.context)

        roles = {}
        parent = getattr(context, '__parent__', None)
        if parent is None:
            for name, setting in globalRolesForPermission(permission):
                roles[name] = setting
        else:
            info = IExtendedGrantInfo(parent)
            for role, setting in info.getRolesForPermission(permission):
                roles[role] = setting

        for name, roleperm in getAdapters((context,), IRolePermissionMap):
            for role, setting in roleperm.getRolesForPermission(permission):
                roles[role] = setting

        return roles.items()

    def getRolesForPrincipal(self, principal):
        context = removeSecurityProxy(self.context)

        roles = {}
        parent = getattr(context, '__parent__', None)
        if parent is None:
            for role, setting in globalRolesForPrincipal(principal):
                roles[role] = setting
        else:
            info = IExtendedGrantInfo(parent)
            for role, setting in info.getRolesForPrincipal(principal):
                roles[role] = setting

        adapters = tuple(getAdapters((context,), IPrincipalRoleMap))
        if adapters and adapters[0][0] == '':
            adapters = adapters[1:] + adapters[:1]

        for name, prinrole in adapters:
            for role, setting in prinrole.getRolesForPrincipal(principal):
                roles[role] = setting

        return roles.items()

    def getPrincipalsForRole(self, role):
        context = removeSecurityProxy(self.context)

        principals = {}
        parent = getattr(context, '__parent__', None)
        if parent is None:
            for principal, setting in globalPrincipalsForRole(role):
                principals[principal] = setting
        else:
            info = IExtendedGrantInfo(parent)
            for principal, setting in info.getPrincipalsForRole(role):
                principals[principal] = setting

        for name, prinrole in getAdapters((context,), IPrincipalRoleMap):
            for principal, setting in prinrole.getPrincipalsForRole(role):
                principals[principal] = setting

        return principals.items()

    def getPrincipalsForPermission(self, permission):
        context = removeSecurityProxy(self.context)

        principals = {}
        parent = getattr(context, '__parent__', None)
        if parent is None:
            for principal, setting in globalPrincipalPermission(permission):
                principals[principal] = setting
        else:
            info = IExtendedGrantInfo(parent)
            for principal, setting in info.getPrincipalsForPermission(permission):
                principals[principal] = setting

        for name, prinper in getAdapters((context,), IPrincipalPermissionMap):
            for principal, setting in prinper.getPrincipalsForPermission(permission):
                principals[principal] = setting

        return principals.items()
