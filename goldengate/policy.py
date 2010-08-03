import time
from notifications import Notification

def action(action, policy, **kwargs):
    """
    Helper for constructing AWS policies. The policy will match AWS request that
    match a particular action. If policy is True the request will be granted. If
    it's False it will be denied. Otherwise, policy is assumed to be a callable
    that will return a Policy object.

    """
    if policy is True:
        policy = AllowPolicy
    elif policy is False:
        policy = DenyPolicy
    return policy(AWSActionMatcher(action), **kwargs)


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


class MatcherPolicy(object):
    def __init__(self, matcher):
        self.matcher = matcher

    def applies_to(self, request):
        return self.matcher.matches(request)


class BooleanPolicy(MatcherPolicy):
    def __init__(self, allow, matcher):
        self.allow = allow
        super(BooleanPolicy, self).__init__(matcher)

    def grant(self, entity, request):
        return self.allow


class AllowPolicy(BooleanPolicy):
    def __init__(self, matcher):
        return super(AllowPolicy, self).__init__(True, matcher)


class DenyPolicy(BooleanPolicy):
    def __init__(self, matcher):
        return super(DenyPolicy, self).__init__(False, matcher)


class TimeLockPolicy(MatcherPolicy):
    """
    A time-lock policy queues requests for execution after some time has
    elapsed. During the time-lock phase of the request a notification will be
    sent to other parties who may be interested in the request. Those parties
    may decide to cancel the request at any period during the time-lock. If the
    request is not cancelled, it will be granted after the lock expires.

    """
    cancelled = False

    def __init__(self, matcher, lock_duration, notification_broker):
        self.lock_duration = lock_duration
        self.notification_broker = notification_broker
        super(TimeLockPolicy, self).__init__(matcher)

    def grant(self, entity, request):
        # Generate UUID, add to list of pending requests, send email with
        # link for cancellation.
        self.notification_broker.send(Notification(['mjmalone@gmail.com'], 'Time-lock engaged!'))
        time.sleep(self.lock_duration)
        return not self.cancelled


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

