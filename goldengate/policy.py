

def action(action, allow):
    """
    Helper for constructing AWS policies. The policy will match AWS request that
    match a particular action. If allow is True the request will be granted. If
    it's False it will be denied.

    """
    if allow:
        return AllowPolicy(AWSActionMatcher(action))
    else:
        return DenyPolicy(AWSActionMatcher(action))


def allow():
    "Helper for constructing a default-allow policy."
    return AllowPolicy(AlwaysMatcher())


def deny():
    "Helper for constructing a default-deny policy."
    return DenyPolicy(AlwaysMatcher())


class MissingPolicyException(Exception):
    pass


class Policy(object):
    policies = []

    def applies_to(self, request):
        """Returns true if this policy applies to the request."""
        raise NotImplementedError

    def grant(self, entity, request):
        """Should we grant entity permission to perform request?"""
        raise NotImplementedError

    @classmethod
    def for_request(self, request):
        import settings
        for policy in getattr(settings, 'POLICIES', []):
            if policy.applies_to(request):
                return policy
        raise MissingPolicyException


class BooleanPolicy(object):
    def __init__(self, allow, matcher):
        self.allow = allow
        self.matcher = matcher

    def applies_to(self, request):
        return self.matcher.matches(request)

    def grant(self, entity, request):
        return self.allow


class AllowPolicy(BooleanPolicy):
    def __init__(self, matcher):
        return super(AllowPolicy, self).__init__(True, matcher)


class DenyPolicy(BooleanPolicy):
    def __init__(self, matcher):
        return super(DenyPolicy, self).__init__(False, matcher)


class Matcher(object):
    def matches(self, request):
        raise NotImplementedError


class AWSActionMatcher(object):
    def __init__(self, action):
        self.action = action

    def matches(self, request):
        action = getattr(request, 'aws_action', None)
        if action is None:
            return False
        else:
            return action == self.action


class AlwaysMatcher(object):
    def matches(self, request):
        return True

