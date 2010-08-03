import smtplib
from collections import namedtuple
from email.mime.text import MIMEText


class NotificationException(Exception):
    pass


Notification = namedtuple('Notification', 'recipients body')


class NotificationBroker(object):
    def send(self, notification):
        print notification


class EmailNotificationBroker(object):
    def __init__(self, sender, host, port, tls=True, username=None, password=None):
        self.sender = sender
        self.host = host
        self.port = port
        self.tls = tls
        self.username = username
        self.password = password

    def send(self, notification):
        smtp = smtplib.SMTP(self.host, self.port)
        if self.tls:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
        if not (self.username is None or self.password is None):
            try:
                smtp.login(self.username, self.password)
            except smtplib.SMTPAuthenticationError, ex:
                raise NotificationException('SMTP Error')

        for recipient in notification.recipients:
            message = MIMEText(notification.body)
            message['From'] = self.sender
            message['To'] = recipient
            message['Subject'] = 'Golden Gate Notification'
            smtp.sendmail(self.sender, [recipient], message.as_string())
        smtp.quit()

