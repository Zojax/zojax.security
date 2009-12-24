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
"""

$Id$
"""
from zope import interface
from zope.component import getAdapters
from zope.security.proxy import removeSecurityProxy
from zope.app.security.settings import Allow

from zope.securitypolicy.interfaces import IPrincipalRoleMap
from zope.securitypolicy.interfaces import IRolePermissionMap
from zope.securitypolicy.interfaces import IPrincipalPermissionMap

from zope.securitypolicy.zopepolicy import ZopeSecurityPolicy

from zope.securitypolicy.zopepolicy import SettingAsBoolean
from zope.securitypolicy.zopepolicy import globalRolesForPrincipal
from zope.securitypolicy.zopepolicy import globalRolesForPermission
from zope.securitypolicy.zopepolicy import globalPrincipalPermissionSetting

from interfaces import IZojaxSecurityPolicy


class CacheEntry(object):

    prinper = None
    roles_adapters = None
    principal_roles_adapters = None
    principal_permission_adapters = None

    def __init__(self):
        self.prin = {}
        self.decision = {}
        self.roles = {}
        self.principal_roles = {}


class SecurityPolicy(ZopeSecurityPolicy):
    interface.implements(IZojaxSecurityPolicy)

    def cache(self, parent):
        cache = self._cache

        if parent in cache:
            return cache[parent]
        else:
            cacheEntry = CacheEntry()
            cache[parent] = cacheEntry
            return cacheEntry

    def cached_roles(self, parent, permission, _allow=Allow):
        cache = self.cache(parent)
        cache_roles = cache.roles
        if permission in cache_roles:
            return cache_roles[permission]

        if parent is None:
            roles = dict(
                [(role, 1) for (role, setting) in globalRolesForPermission(permission)
                 if setting is _allow])
            cache_roles[permission] = roles
            return roles

        roles = self.cached_roles(
            removeSecurityProxy(getattr(parent, '__parent__', None)), permission)

        # cache adaters
        rolepers = cache.roles_adapters
        if rolepers is None:
            rolepers = tuple(getAdapters((parent,), IRolePermissionMap))
            cache.roles_adapters = rolepers

        if rolepers:
            roles = roles.copy()
            for name, roleper in rolepers:
                for role, setting in roleper.getRolesForPermission(permission):
                    if setting is _allow:
                        roles[role] = 1
                    elif role in roles:
                        del roles[role]

        cache_roles[permission] = roles
        return roles

    def cached_principal_roles(self, parent, principal, 
                               SettingAsBoolean=SettingAsBoolean):
        cache = self.cache(parent)
        cache_principal_roles = cache.principal_roles
        if principal in cache_principal_roles:
            return cache_principal_roles[principal]

        if parent is None:
            roles = dict(
                [(role, SettingAsBoolean[setting])
                 for (role, setting) in globalRolesForPrincipal(principal)]
                 )
            roles['zope.Anonymous'] = True # Everybody has Anonymous
            cache_principal_roles[principal] = roles
            return roles

        roles = self.cached_principal_roles(
            removeSecurityProxy(getattr(parent, '__parent__', None)), principal)

        roles = roles.copy()

        # cache adaters
        adapters = cache.principal_roles_adapters
        if adapters is None:
            adapters = tuple(getAdapters((parent,), IPrincipalRoleMap))
            if adapters and adapters[0][0] == '':
                adapters = adapters[1:] + adapters[:1]
            cache.principal_roles_adapters = adapters

        for name, prinrole in adapters:
            for role, setting in prinrole.getRolesForPrincipal(principal):
                roles[role] = SettingAsBoolean[setting]

        cache_principal_roles[principal] = roles
        return roles

    def cached_prinper(self, parent, principal, groups, permission):
        # Compute the permission, if any, for the principal.
        cache = self.cache(parent)
        cache_prin = cache.prin

        if principal in cache_prin:
            cache_prin_per = cache_prin[principal]
        else:
            cache_prin_per = cache_prin[principal] = {}
        
        if permission in cache_prin_per:
            return cache_prin_per[permission]

        if parent is None:
            prinper = SettingAsBoolean[
                globalPrincipalPermissionSetting(permission, principal, None)
                ]
            cache_prin_per[permission] = prinper
            return prinper

        # cache adaters
        adapters = cache.principal_permission_adapters
        if adapters is None:
            adapters = tuple(getAdapters((parent,), IPrincipalPermissionMap))
            cache.principal_permission_adapters = adapters

        for name, prinper in adapters:
            prinper = SettingAsBoolean[
                prinper.getSetting(permission, principal, None)]
            if prinper is not None:
                cache_prin_per[permission] = prinper
                return prinper

        parent = removeSecurityProxy(getattr(parent, '__parent__', None))
        prinper = self.cached_prinper(parent, principal, groups, permission)
        cache_prin_per[permission] = prinper
        return prinper

    def cached_decision(self, parent, principal, groups, permission):
        # Return the decision for a principal and permission
        cache = self.cache(parent)
        cache_decision = cache.decision

        if principal in cache_decision:
            cache_decision_prin = cache_decision[principal]
        else:
            cache_decision_prin = cache_decision[principal] = {}

        if permission in cache_decision_prin:
            return cache_decision_prin[permission]

        # cache_decision_prin[permission] is the cached
        # decision for a principal and permission.
        decision = self.cached_prinper(parent, principal, groups, permission)
        if (decision is None) and groups:
            decision = self._group_based_cashed_prinper(
                parent, principal, groups, permission)

        if decision is not None:
            cache_decision_prin[permission] = decision
            return decision

        roles = self.cached_roles(parent, permission)
        if roles:
            prin_roles = self.cached_principal_roles(parent, principal)
            if groups:
                prin_roles = self.cached_principal_roles_w_groups(
                    parent, principal, groups, prin_roles)
            for role, setting in prin_roles.items():
                if setting and (role in roles):
                    cache_decision_prin[permission] = decision = True
                    return decision

        cache_decision_prin[permission] = decision = False
        return decision
