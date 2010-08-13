"""
Thread-safe in-memory key-value store backend.

Just for testing. This isn't persistent. Don't actually use it.

Example configuration for Django settings:

    KEY_VALUE_STORE_BACKEND = 'locmem://'

"""

try:
    import cPickle as pickle
except ImportError:
    import pickle
from base import BaseStorage

class StorageClass(BaseStorage):
    def __init__(self, _, params):
        BaseStorage.__init__(self, params)
        self._db = {}
        self._lock = RWLock()

    def set(self, key, value):
        self._lock.writer_enters()
        try:
            self._db[key] = pickle.dumps(value)
        finally:
            self._lock.writer_leaves()

    def get(self, key):
        self._lock.reader_enters()
        # Python 2.3 and 2.4 don't allow combined try-except-finally blocks.
        try:
            try:
                return pickle.loads(self._db[key])
            except KeyError:
                return None
        finally:
            self._lock.reader_leaves()

    def delete(self, key):
        self._lock.writer_enters()
        # Python 2.3 and 2.4 don't allow combined try-except-finally blocks.
        try:
            try:
                del self._db[key]
            except KeyError:
                pass
        finally:
            self._lock.writer_leaves()

    def has_key(self, key):
        self._lock.reader_enters()
        try:
            return key in self._db
        finally:
            self._lock.reader_leaves()


"""
Synchronization primitives:
    - reader-writer lock (preference to writers)

(Contributed to Django by eugene@lazutkin.com)
(Borrowed from Django for use in Golden Gate by mike@simplegeo.com)
"""
import threading

class RWLock:
    """
    Classic implementation of reader-writer lock with preference to writers.

    Readers can access a resource simultaneously.
    Writers get an exclusive access.

    API is self-descriptive:
        reader_enters()
        reader_leaves()
        writer_enters()
        writer_leaves()
    """
    def __init__(self):
        self.mutex     = threading.RLock()
        self.can_read  = threading.Semaphore(0)
        self.can_write = threading.Semaphore(0)
        self.active_readers  = 0
        self.active_writers  = 0
        self.waiting_readers = 0
        self.waiting_writers = 0

    def reader_enters(self):
        self.mutex.acquire()
        try:
            if self.active_writers == 0 and self.waiting_writers == 0:
                self.active_readers += 1
                self.can_read.release()
            else:
                self.waiting_readers += 1
        finally:
            self.mutex.release()
        self.can_read.acquire()

    def reader_leaves(self):
        self.mutex.acquire()
        try:
            self.active_readers -= 1
            if self.active_readers == 0 and self.waiting_writers != 0:
                self.active_writers  += 1
                self.waiting_writers -= 1
                self.can_write.release()
        finally:
            self.mutex.release()

    def writer_enters(self):
        self.mutex.acquire()
        try:
            if self.active_writers == 0 and self.waiting_writers == 0 and self.active_readers == 0:
                self.active_writers += 1
                self.can_write.release()
            else:
                self.waiting_writers += 1
        finally:
            self.mutex.release()
        self.can_write.acquire()

    def writer_leaves(self):
        self.mutex.acquire()
        try:
            self.active_writers -= 1
            if self.waiting_writers != 0:
                self.active_writers  += 1
                self.waiting_writers -= 1
                self.can_write.release()
            elif self.waiting_readers != 0:
                t = self.waiting_readers
                self.waiting_readers = 0
                self.active_readers += t
                while t > 0:
                    self.can_read.release()
                    t -= 1
        finally:
            self.mutex.release()
