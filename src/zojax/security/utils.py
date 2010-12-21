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
from zope.component import getUtility
from zope.security.proxy import removeSecurityProxy
from zope.security.management import queryInteraction
from zope.app.security.interfaces import IAuthentication, PrincipalLookupError
from zope.app.security.principalregistry import Principal

from interfaces import IZojaxSecurityPolicy, _


def getPrincipal(id=None):
    """ get current interaction principal """
    if id is None:
        interaction = queryInteraction()

        if interaction is not None:
            for participation in interaction.participations:
                if participation.principal is not None:
                    return participation.principal
    else:
        try:
            return getUtility(IAuthentication).getPrincipal(id)
        except PrincipalLookupError:
            return Principal('unknown', _('Unknown'), _('Unknown'), 'unknown', 'unknown')



def getPrincipals(ids):
    auth = getUtility(IAuthentication)

    for pid in ids:
        try:
            principal = auth.getPrincipal(pid)
        except PrincipalLookupError:
            continue

        yield principal


def checkPermissionForPrincipal(principal, permission, object):
    interaction = queryInteraction()

    if IZojaxSecurityPolicy.providedBy(interaction):
        return interaction.cached_decision(
            removeSecurityProxy(object), principal.id,
            interaction._groupsFor(principal), permission)

    return False
