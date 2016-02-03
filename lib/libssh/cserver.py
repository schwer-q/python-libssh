#
# Copyright (c) 2016, Quentin Schwerkolt
# All rights reserved.
#
# Use is subject to license terms
#

from ctypes import *
from functools import wraps

try:
    clibssh = cdll.LoadLibrary("libssh.so")
except OSError:
    try:
        clibssh = cdll.LoadLibrary("libssh.dylib")
    except OSError:
        raise Exception("Could not load libssh C library.")

(
    SSH_BIND_OPTIONS_BINDADDR,
    SSH_BIND_OPTIONS_BINDPORT,
    SSH_BIND_OPTIONS_BINDPORT_STR,
    SSH_BIND_OPTIONS_HOSTKEY,
    SSH_BIND_OPTIONS_DSAKEY,
    SSH_BIND_OPTIONS_RSAKEY,
    SSH_BIND_OPTIONS_BANNER,
    SSH_BIND_OPTIONS_LOG_VERBOSITY,
    SSH_BIND_OPTIONS_LOG_VERBOSITY_STR
) = range(9)

def libssh(restype=None, argtypes=None):
    def wrapper(function):
        fname = function.__name__
        cfunction = getattr(clibssh, function.__name__)
        if restype is not None:
            cfunction.restype = restype
        if argtypes is not None:
            cfunction.argtypes = argtypes

        @wraps(function)
        def nfunction(*args):
            return cfunction(*args)
        return nfunction
    return wrapper

@libssh(restype=c_void_p)
def ssh_bind_new(): pass

@libssh(argtypes=[c_void_p, c_int, c_void_p], restype=c_int)
def ssh_bind_options_set(sshbind, key, value): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_bind_listen(sshbind): pass

@libssh(argtypes=[c_void_p, c_void_p, c_void_p], restype=c_int)
def ssh_bind_set_callbacks(sshbind, callbacks, userdata): pass

@libssh(argtypes=[c_void_p, c_int], restype=c_int)
def ssh_bind_set_blocking(sshbind, blocking): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_bind_get_fd(sshbind): pass

@libssh(argtypes=[c_void_p, c_int], restype=c_int)
def ssh_bind_set_fd(sshbind, fd): pass

@libssh(argtypes=[c_void_p])
def ssh_bind_fd_toaccept(sshbind): pass

@libssh(argtypes=[c_void_p, c_void_p], restype=c_int)
def ssh_bind_accept(sshbind, session): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_handle_key_exchange(session): pass

@libssh(argtypes=[c_void_p])
def ssh_bind_free(sshbind): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_reply_default(msg): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_auth_user(msg): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_auth_password(msg): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_message_auth_publickey(msg): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_auth_publickey_state(msg): pass

@libssh(argtypes=[c_void_p, c_int], restype=c_int)
def ssh_message_auth_reply_success(msg, partial): pass

@libssh(argtypes=[c_void_p, c_void_p, c_void_p], restype=c_int)
def ssh_message_auth_reply_pk_ok(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_auth_reply_pk_ok_simple(): pass

@libssh(argtypes=[c_void_p, c_int], restype=c_int)
def ssh_message_auth_set_methods(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_service_reply_success(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_service_service(): pass

@libssh(argtypes=[c_void_p, c_uint16], restype=c_int)
def ssh_message_global_request_reply_success(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_void_p])
def ssh_set_message_callback(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_execute_message_callbacks(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_channel_request_open_originator(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_channel_request_open_originator_port(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_channel_request_open_destination(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_channel_request_open_destination_port(): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_message_channel_request_channel(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_channel_request_pty_term(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_channel_request_pty_width(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_channel_request_pty_height(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_channel_request_pty_pxwidth(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_channel_request_pty_pxheight(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_channel_request_env_name(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_channel_request_env_value(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_channel_request_command(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_channel_request_subsystem(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_message_global_request_address(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_global_request_port(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_int, c_char_p, c_int], restype=c_int)
def ssh_channel_open_reverse_forward(): pass

@libssh(argtypes=[c_void_p, c_int], restype=c_int)
def ssh_channel_request_send_exit_status(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_int, c_char_p, c_char_p], restype=c_int)
def ssh_channel_request_send_exit_signal(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_uint32], restype=c_int)
def ssh_channel_write_stderr(): pass
