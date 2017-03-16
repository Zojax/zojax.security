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
from zope import interface
from zope.component import getUtilitiesFor
from zope.schema.interfaces import IVocabularyFactory
from zope.schema.vocabulary import SimpleTerm, SimpleVocabulary

from interfaces import IPublicRole, IPublicPermission


class Vocabulary(SimpleVocabulary):

    def getTerm(self, value):
        try:
            return self.by_value[value]
        except KeyError:
            return self.by_value[self.by_value.keys()[0]]


class RolesVocabulary(object):
    """
    >>> from zope import interface, component
    >>> from zojax.security.vocabulary import RolesVocabulary
    >>> factory = RolesVocabulary()

    >>> list(factory(None))
    []

    >>> from zojax.security.interfaces import IPublicRole
    >>> class Role(object):
    ...     interface.implements(IPublicRole)
    >>> r = Role()
    >>> r.id = 'portal.Member'
    >>> r.title = 'Portal member'

    >>> component.provideUtility(r, name='portla.Member')

    >>> for term in factory(None):
    ...     print term.value, term.title
    portal.Member Portal member

    """
    interface.implements(IVocabularyFactory)

    def __call__(self, context, **kw):
        roles = []
        for name, role in getUtilitiesFor(IPublicRole):
            if role.title != 'Site Manager' and not role.id:
                continue
            term = SimpleTerm(role.id, role.id, role.title)
            term.description = getattr(role, 'description', u'')
            roles.append((role.title, term))
        roles.sort()
        return Vocabulary([term for title, term in roles])


class PermissionsVocabulary(object):
    """
    >>> from zope import interface, component

    >>> factory = PermissionsVocabulary()
    >>> list(factory(None))
    []

    >>> from zojax.security.interfaces import IPublicPermission
    >>> class Permission(object):
    ...     interface.implements(IPublicPermission)
    >>> r = Permission()
    >>> r.id = 'permission1'
    >>> r.title = 'Permission1'

    >>> component.provideUtility(r, name='permission1')

    >>> for term in factory(None):
    ...     print term.value, term.title
    permission1 Permission1

    """
    interface.implements(IVocabularyFactory)

    def __call__(self, context, **kw):
        perms = []
        for name, perm in getUtilitiesFor(IPublicPermission):
            perms.append((perm.title, SimpleTerm(perm.id, perm.id, perm.title)))
        perms.sort()
        return Vocabulary([term for title, term in perms])
