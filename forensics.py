'''
forensics.py -- shared forensic logger for SLI-KUBE.

COMP 5710/6710 SQA project, team AubreyFoote (Fall 2026).

Every instrumented method calls getLogger() and writes events to
logs/forensics.log. Each line records when it happened, which process,
which module/function/line, and what happened, so a run can be
reconstructed afterwards (who ran the scanner, on which files, which
files failed to parse and why, what was found).

Rule followed throughout: log the *names* of secret keys and the
fingerprints of files, never the secret values themselves. A log that
leaks the passwords it found would be a new security problem.

Set SLIKUBE_FORENSICS=0 to turn logging off (fuzz.py does this so its
thousands of random calls do not flood the forensic log).
'''

import hashlib
import logging
import os

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'forensics.log')
LOG_FORMAT = '%(asctime)s | %(levelname)-7s | pid=%(process)d | %(module)s.%(funcName)s:%(lineno)d | %(message)s'


def getLogger():
    logger = logging.getLogger('slikube.forensics')
    if not logger.handlers:
        os.makedirs(LOG_DIR, exist_ok=True)
        handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    logger.disabled = os.environ.get('SLIKUBE_FORENSICS', '1') == '0'
    return logger


def fileFingerprint(path):
    '''Size and SHA-256 of a file, so the log proves exactly which content was scanned.'''
    try:
        with open(path, 'rb') as f:
            data = f.read()
        return 'size=%dB sha256=%s' % (len(data), hashlib.sha256(data).hexdigest())
    except OSError as err:
        return 'unreadable (%s)' % type(err).__name__
