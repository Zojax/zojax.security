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
from zope.component import getUtility
from zope.security.proxy import removeSecurityProxy
from zope.security.interfaces import IPrincipal, IGroup, IGroupAwarePrincipal
from zope.app.security.interfaces import IAuthentication

from interfaces import IPrincipalGroups


class PrincipalGroups(object):
    interface.implements(IPrincipalGroups)

    _cached = None

    def __init__(self, principal):
        self.principal = removeSecurityProxy(principal)

    def getGroups(self, type=None):
        if type is None:
            type = IPrincipal

        principal = self.principal

        if IGroupAwarePrincipal.providedBy(principal):
            if principal.groups:
                seen = set()
                principals = getUtility(IAuthentication)

                stack = [iter(principal.groups)]

                if IGroup.providedBy(principal):
                    stack.append(iter([principal.id]))

                while stack:
                    try:
                        group_id = stack[-1].next()
                    except StopIteration:
                        stack.pop()
                    else:
                        if group_id not in seen:
                            group = principals.getPrincipal(group_id)

                            seen.add(group_id)
                            stack.append(iter(group.groups))

                            if type.providedBy(group):
                                yield group
