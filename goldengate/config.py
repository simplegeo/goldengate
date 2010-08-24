

class Config(object):
    def __init__(self):
        self.settings = {}
        for setting in SettingMeta.known_settings.values():
            self.settings[setting.name] = setting()

    def __getattr__(self, name):
        if name not in self.settings:
            raise AttributeError('Missing setting: %s' % (name,))
        return self.settings[name].get()

    def __setattr__(self, name, value):
        if name != 'settings' and name in self.settings:
            raise AttributeError('Invalid access!')
        super(Config, self).__setattr__(name, value)

    def __str__(self):
        return "\n".join(str(setting) for setting in self.settings.itervalues())

    def set(self, name, value):
        self.settings[name].set(value)


class SettingMeta(type):
    known_settings = {}

    def __new__(cls, name, bases, attrs):
        setting = super(SettingMeta, cls).__new__(cls, name, bases, attrs)
        cls.known_settings[setting.name] = setting
        return setting


class Setting(object):
    __metaclass__ = SettingMeta

    name = None
    value = None
    default = None

    def __init__(self):
        if self.default is not None:
            self.set(self.default)

    def set(self, value):
        self.value = value

    def get(self):
        return self.value

    def __str__(self):
        return "%s: %s" % (self.name, self.value or self.default)


class ClassSetting(Setting):
    def set(self, value):
        components = value.split('.')
        module = __import__('.'.join(components[:-1]))
        class_name = components.pop(-1)
        for component in components[1:]:
            module = getattr(module, component)
        self.value = getattr(module, class_name)


class Auditor(ClassSetting):
    name = 'auditor'
    default = 'goldengate.sausagefactory.LogAuditTrail'


class AuditorArgs(Setting):
    name = 'audit_args'
    default = []


class RemoteHost(Setting):
    name = 'remote_host'
    default = 'ec2.amazonaws.com'


class Credentials(Setting):
    name = 'credentials'
    default = []


class CredentialStore(ClassSetting):
    name = 'credential_store'
    default = 'goldengate.credentials.StaticCredentialStore'


class StorageBackend(Setting):
    name = 'storage_backend'
    default = 'locmem://'


class AWSKey(Setting):
    name = 'aws_key'
    default = ''


class AWSSecret(Setting):
    name = 'aws_secret'
    default = ''


class Policies(Setting):
    name = 'policies'
    default = []
