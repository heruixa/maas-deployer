#
# Copyright 2015 Canonical, Ltd.
#
# Contains utility functions

import argparse
import collections
import logging
import os
import subprocess
import time

log = logging.getLogger('vmaas.main')

USER_DATA_DIR = os.path.join(os.getcwd(), 'user-files')
USER_PRESEED_DIR = os.path.join(USER_DATA_DIR, 'preseeds')


def retry_on_exception(max_retries=5, exc_tuple=None):
    if not exc_tuple:
        exc_tuple = Exception
    else:
        # Ensure tuple otherwise they'll get ignored
        exc_tuple = tuple(exc_tuple)

    def _retry_on_exception(f):
        def __retry_on_exception(*args, **kwargs):
            retries = 0
            delay = 1
            while True:
                try:
                    return f(*args, **kwargs)
                except exc_tuple:  # pylint: disable=E0712,W0703
                    retries += 1
                    if retries >= max_retries:
                        log.debug("Command failed and max retries reached")
                        raise

                    log.debug("Command failed - retrying in %ss", (delay))
                    time.sleep(delay)
                    delay += 2

        return __retry_on_exception
    return _retry_on_exception


def execc(cmd, stdin=None, pipedcmds=None, fatal=True, suppress_stderr=False,
          _pipe_stack=None):
    """Execute command with subprocess.

    If pipedcmds are provided, this function is called recursively piping
    stdout to next stdin and returning stdout of final process.

    When using piped commands this function will maintain a stack of executed
    commands in _pipe_stack so as to be able to track failures. Usage of this
    parameter is restricted to this function.
    """
    _input = None

    # Abridge stdin for log if provided
    _stdin = ''
    if stdin:
        _stdin = stdin
        if type(stdin) == file:
            _stdin = "<type 'file'>"
        else:
            if len(_stdin) > 10:
                _stdin = "%s..." % _stdin[:10]

    log.debug("Executing: '%s' stdin='%s'", ' '.join(cmd), _stdin)

    if stdin:
        if type(stdin) == file:
            p = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdin.close()
        else:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            _input = stdin
    else:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

    if not pipedcmds:
        ret = p.communicate(input=_input)

        bad = None
        if _pipe_stack:
            for pp, pcmd in _pipe_stack:
                pp.wait()
                if pp.returncode:
                    bad = (pp.returncode, pp.stderr.read(), pcmd)
                    break

        if fatal and (p.returncode or bad):
            if bad:
                rc = bad[0]
                stderr = bad[1]
                cmd = bad[2]
            else:
                rc = p.returncode
                stderr = ret[1]

            if not suppress_stderr:
                log.error(stderr)
                print stderr

            raise subprocess.CalledProcessError(rc, ' '.join(cmd),
                                                output=stderr)

        return ret
    else:
        if not _pipe_stack:
            _pipe_stack = []

        _pipe_stack.append((p, cmd))

    return execc(pipedcmds[0], stdin=p.stdout, pipedcmds=pipedcmds[1:],
                 _pipe_stack=_pipe_stack)


def exec_script_remote(user, host, script):
    """Execute a script within an SSH session."""
    log.debug("Executing script on remote host '%s'", host)
    cmd = ['ssh', '-i', os.path.expanduser('~/.ssh/id_maas'),
           '-o', 'UserKnownHostsFile=/dev/null',
           '-o', 'StrictHostKeyChecking=no', '%s@%s' % (user, host)]
    return execc(cmd, stdin=script.strip())


def virsh(cmd, fatal=True):
    _cmd = ['virsh', '-c', CONF.remote]
    _cmd.extend(cmd)
    return execc(_cmd, fatal=fatal)


def flatten(d, parent_key=''):
    """
    Flattens a nested set of dictionaries within dictionaries.
    The resultant map will contain all of the leaf elements contained
    in the original dictionaries, with the keys indicating the original
    hierarchy of the nested dictionaries.

    e.g:
    {
        'foo': 'bar',
        'baz': {
            'one': 1,
            'two': 2,
            'three': {
                'eh': 'a',
                'bee': 'b',
                'see': 'c'
            }
        },
    }

    will be flattened to:
    {
        'foo': 'bar',
        'baz_one': 1,
        'baz_two': 2,
        'baz_three_eh': 'a',
        'baz_three_bee': 'b',
        'baz_three_see': 'c',
    }

    :param d: a dictionary containing other dictionaries which should
              be flattened.
    :param parent_key: the parent element's key. Primarily used internally
                       to keep track of the key during recursion.
    """
    items = []
    for k, v in d.items():
        new_key = parent_key + '_' + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key).items())
        else:
            items.append((new_key, v))

    return dict(items)


class OptParser(object):
    def __init__(self):
        desc = "Deploys a MAAS environment"
        self._parser = argparse.ArgumentParser(description=desc)
        self._args = None

    def __getattr__(self, attr):
        if attr not in self.__dict__:
            if hasattr(self.args, attr):
                return getattr(self.args, attr)

        raise AttributeError("%r object has no attribute %r" %
                             (self.__class__, attr))

    def parse_args(self):
        self._args = self._parser.parse_args()

    @property
    def args(self):
        return self._args

    @property
    def parser(self):
        return self._parser


CONF = OptParser()
