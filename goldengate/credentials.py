from collections import namedtuple


Credential = namedtuple('Credentials', 'entity key secret')


class CredentialStore(object):
    "Abstract credentials store."

    def for_key(self, key):
        return None

    def for_entity(self, entity):
        return None


class StaticCredentialStore(CredentialStore):
    def __init__(self, credentials):
        # Must be a single set of credentials for each key
        assert len(set([credential.key for credential in credentials])) == len(credentials)
        self.credentials = credentials

    def for_key(self, key):
        """
        Returns a single credential for a specific key or None if no
        credentials exist.

        """
        for credential in self.credentials:
            if credential.key == key:
                return credential
        return None

    def for_entity(self, entity):
        "Returns a list of credentials for a particular entity."
        return [credential for credential in self.credentials if credential.entity == entity]
