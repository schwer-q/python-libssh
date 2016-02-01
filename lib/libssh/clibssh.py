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
    SSH_KEX,
    SSH_HOSTKEYS,
    SSH_CRYPT_C_S,
    SSH_CRYPT_S_C,
    SSH_MAC_C_S,
    SSH_MAC_S_C,
    SSH_COMP_C_S,
    SSH_COMP_S_C,
    SSH_LANG_C_S,
    SSH_LANG_S_C
) = range(10)

SSH_CRYPT       = 2
SSH_MAC         = 3
SSH_COMP        = 4
SSH_LANG        = 5

(
    SSH_AUTH_ERROR,
    SSH_AUTH_SUCCESS,
    SSH_AUTH_DENIED,
    SSH_AUTH_PARTIAL,
    SSH_AUTH_INFO,
    SSH_AUTH_AGAIN
) = range(-1, 5)

SSH_AUTH_METHOD_UNKNOWN         = 0x0000
SSH_AUTH_METHOD_NONE            = 0x0001
SSH_AUTH_METHOD_PASSWORD        = 0x0002
SSH_AUTH_METHOD_PUBLICKEY       = 0x0004
SSH_AUTH_METHOD_HOSTBASED       = 0x0008
SSH_AUTH_METHOD_INTERACTIVE     = 0x0010
SSH_AUTH_METHOD_GSSAPI_MIC      = 0x0020

(
    SSH_REQUEST_AUTH,
    SSH_REQUEST_CHANNEL_OPEN,
    SSH_REQUEST_CHANNEL,
    SSH_REQUEST_SERVICE,
    SSH_REQUEST_GLOBAL
) = range(1, 6)

(
    SSH_CHANNEL_UNKNOWN,
    SSH_CHANNEL_SESSION,
    SSH_CHANNEL_DIRECT_TCPIP,
    SSH_CHANNEL_FORWARDED_TCPIP,
    SSH_CHANNEL_X11
) = range(5)

(
    SSH_CHANNEL_REQUEST_UNKNOWN,
    SSH_CHANNEL_REQUEST_PTY,
    SSH_CHANNEL_REQUEST_EXEC,
    SSH_CHANNEL_REQUEST_SHELL,
    SSH_CHANNEL_REQUEST_ENV,
    SSH_CHANNEL_REQUEST_SUBSYSTEM,
    SSH_CHANNEL_REQUEST_WINDOW_CHANGE,
    SSH_CHANNEL_REQUEST_X11
) = range(8)

(
    SSH_GLOBAL_REQUEST_UNKNOWN,
    SSH_GLOBAL_REQUEST_TCPIP_FORWARD,
    SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD
) = range(3)


(
    SSH_PUBLICKEY_STATE_ERROR,
    SSH_PUBLICKEY_STATE_NONE,
    SSH_PUBLICKEY_STATE_VALID,
    SSH_PUBLICKEY_STATE_WRONG
) = range(-1, 3)

SSH_CLOSED              = 0x01
SSH_READ_PENDING        = 0x02
SSH_CLOSED_ERROR        = 0x04
SSH_WRITE_PENDING       = 0x08

(
    SSH_NO_ERROR,
    SSH_REQUEST_DENIED,
    SSH_FATAL,
    SSH_EINTR
) = range(4)

(
    SSH_KEYTYPE_UNKNOWN,
    SSH_KEYTYPE_DSS,
    SSH_KEYTYPE_RSA,
    SSH_KEYTYPE_RSA1,
    SSH_KEYTYPE_ECDSA,
    SSH_KEYTYPE_ED25519
) = range(6)

(
    SSH_KEY_CMP_PUBLIC,
    SSH_KEY_CMP_PRIVATE
) = range(2)

SSH_OK          = 0
SSH_ERROR       = -1
SSH_AGAIN       = -2
SSH_EOF         = -127

(
    SSH_LOG_NOLOG,
    SSH_LOG_WARNING,
    SSH_LOG_PROTOCOL,
    SSH_LOG_PACKET,
    SSH_LOG_FUNCTIONS
) = range(5)

(
    SSH_OPTIONS_HOST,
    SSH_OPTIONS_PORT,
    SSH_OPTIONS_PORT_STR,
    SSH_OPTIONS_FD,
    SSH_OPTIONS_USER,
    SSH_OPTIONS_SSH_DIR,
    SSH_OPTIONS_IDENTITY,
    SSH_OPTIONS_ADD_IDENTITY,
    SSH_OPTIONS_KNOWNHOSTS,
    SSH_OPTIONS_TIMEOUT,
    SSH_OPTIONS_TIMEOUT_USEC,
    SSH_OPTIONS_SSH1,
    SSH_OPTIONS_SSH2,
    SSH_OPTIONS_LOG_VERBOSITY,
    SSH_OPTIONS_LOG_VERBOSITY_STR,
    SSH_OPTIONS_CIPHERS_C_S,
    SSH_OPTIONS_CIPHERS_S_C,
    SSH_OPTIONS_COMPRESSION_C_S,
    SSH_OPTIONS_COMPRESSION_S_C,
    SSH_OPTIONS_PROXYCOMMAND,
    SSH_OPTIONS_BINDADDR,
    SSH_OPTIONS_STRICTHOSTKEYCHECK,
    SSH_OPTIONS_COMPRESSION,
    SSH_OPTIONS_COMPRESSION_LEVEL,
    SSH_OPTIONS_KEY_EXCHANGE,
    SSH_OPTIONS_HOSTKEYS,
    SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
    SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
    SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
    SSH_OPTIONS_HMAC_C_S,
    SSH_OPTIONS_HMAC_S_C
) = range(31)

SSH_SCP_WRITE           = 0
SSH_SCP_READ            = 1
SSH_SCP_RECURSIVE       = 0x10

(
    SSH_SCP_REQUEST_NEWDIR,
    SSH_SCP_REQUEST_NEWFILE,
    SSH_SCP_REQUEST_EOF,
    SSH_SCP_REQUEST_ENDDIR,
    SSH_SCP_REQUEST_WARNING
) = range(1, 6)

(
    SSH_PUBLICKEY_HASH_SHA1,
    SSH_PUBLICKEY_HASH_MD5
) = range(2)

NULL = 0
SSH_EOF = -127
SSH_OK = 0


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


@libssh(argtypes=[c_void_p, c_int], restype=c_int)
def ssh_blocking_flush(): pass

@libssh(argtypes=[c_void_p, c_int], restype=c_void_p)
def ssh_channel_accept_x11(): pass

@libssh(argtypes=[c_void_p, c_int, c_int], restype=c_int)
def ssh_channel_change_pty_size(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_close(): pass

@libssh(argtypes=[c_void_p])
def ssh_channel_free(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_get_exit_status(): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_channel_get_session(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_is_closed(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_is_eof(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_is_open(): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_channel_new(): pass

# @libssh(argtypes=[c_void_p], restype=c_int)
# def ssh_channel_open_auth_agent(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_int, c_char_p, c_int], restype=c_int)
def ssh_channel_open_forward(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_open_session(): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int], restype=c_int)
# def ssh_channel_open_x11(): pass

@libssh(argtypes=[c_void_p, c_int], restype=c_int)
def ssh_channel_poll(): pass

# @libssh(argtypes=[c_void_p, c_int, c_int], restype=c_int)
# def ssh_channel_poll_timeout(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_uint32, c_int], restype=c_int)
def ssh_channel_read(): pass

# @libssh(argtypes=[c_void_p, c_void_p, c_uint32, c_int, c_int], restype=c_int)
# def ssh_channel_read_timeout(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_uint32, c_int], restype=c_int)
def ssh_channel_read_nonblocking(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_char_p], restype=c_int)
def ssh_channel_request_env(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_channel_request_exec(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_request_pty(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_int, c_int], restype=c_int)
def ssh_channel_request_pty_size(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_request_shell(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_channel_request_send_signal(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_request_sftp(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_channel_request_subsystem(): pass

@libssh(argtypes=[c_void_p, c_int, c_char_p, c_char_p, c_int], restype=c_int)
def ssh_channel_request_x11(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_channel_send_eof(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_void_p, c_void_p], restype=c_int)
def ssh_channel_select(): pass

@libssh(argtypes=[c_void_p, c_int])
def ssh_channel_set_blocking(): pass

# @libssh(argtypes=[c_void_p, c_void_p])
# def ssh_channel_set_counter(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_uint32], restype=c_int)
def ssh_channel_write(): pass

@libssh(argtypes=[c_void_p], restype=c_uint32)
def ssh_channel_window_size(): pass

@libssh(argtypes=[c_void_p, c_char_p, POINTER(c_void_p), POINTER(c_int)], restype=c_int)
def ssh_try_publickey_from_file(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_auth_list(): pass

@libssh(argtypes=[c_char_p], restype=c_char_p)
def ssh_basename(): pass

@libssh(argtypes=[POINTER(c_char_p)])
def ssh_clean_pubkey_hash(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_connect(): pass

@libssh(restype=c_char_p)
def ssh_copyright(): pass

@libssh(argtypes=[c_void_p])
def ssh_disconnect(): pass

@libssh(argtypes=[c_char_p], restype=c_char_p)
def ssh_dirname(): pass

@libssh(restype=c_int)
def ssh_finalize(): pass

@libssh(argtypes=[c_void_p, c_int], restype=c_void_p)
def ssh_forward_accept(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_int], restype=c_int)
def ssh_forward_cancel(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_int, POINTER(c_int)], restype=c_int)
def ssh_forward_listen(): pass

# @libssh(argtypes=[c_void_p, c_int, c_int, POINTER(c_int)], restype=c_void_p)
# def ssh_channel_accept_forward(): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int], restype=c_int)
# def ssh_channel_cancel_forward(): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int, POINTER(c_int)], restype=c_int)
# def ssh_channel_listen_forward(): pass

@libssh(argtypes=[c_void_p])
def ssh_free(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_get_disconnect_message(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_get_error(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_get_error_code(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_get_fd(): pass

@libssh(argtypes=[POINTER(c_uint8), c_uint32], restype=c_char_p)
def ssh_get_hexa(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_get_issue_banner(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_get_openssh_version(): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_get_pubkey(): pass

@libssh(argtypes=[c_void_p, POINTER(POINTER(c_uint8))], restype=c_int)
def ssh_get_pubkey_hash(): pass

# @libssh(argtypes=[c_void_p, POINTER(c_void_p)], restype=c_int)
# def ssh_get_publickey(): pass

# @libssh(argtypes=[c_void_p, c_int, POINTER(POINTER(c_uint8)), POINTER(c_uint32)], restype=c_int)
# def ssh_get_publickey_hash(): pass

@libssh(argtypes=[c_void_p, c_int, c_int], restype=c_int)
def ssh_get_random(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_get_version(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_get_status(): pass

# @libssh(argtypes=[c_void_p], restype=c_int)
# def ssh_get_poll_flags(): pass

@libssh(restype=c_int)
def ssh_init(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_is_blocking(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_is_connected(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_is_server_known(): pass

# @libssh(argtypes=[c_void_p], restype=c_int)
# def ssh_get_version(): pass

# @libssh(argtypes=[c_int], restype=c_int)
# def ssh_set_log_level(): pass

# @libssh(restype=c_int)
# def ssh_get_log_level(): pass

# @libssh(restype=c_void_p)
# def ssh_get_log_userdata(): pass

# @libssh(argtypes=[c_void_p], restype=c_int)
# def ssh_set_log_userdata(): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_message_channel_request_open_reply_accept(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_channel_request_reply_success(): pass

@libssh(argtypes=[c_void_p])
def ssh_message_free(): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_message_get(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_subtype(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_message_type(): pass

@libssh(argtypes=[c_char_p, c_int], restype=c_int)
def ssh_mkdir(): pass

@libssh(restype=c_void_p)
def ssh_new(): pass

@libssh(argtypes=[c_void_p, POINTER(c_void_p)], restype=c_int)
def ssh_options_copy(): pass

@libssh(argtypes=[c_void_p, POINTER(c_int), POINTER(c_char_p)], restype=c_int)
def ssh_options_getopt(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_options_parse_config(): pass

@libssh(argtypes=[c_void_p, c_int, c_void_p], restype=c_int)
def ssh_options_set(): pass

# @libssh(argtypes=[c_void_p, c_int, POINTER(c_char_p)], restype=c_int)
# def ssh_options_get(): pass

# @libssh(argtypes=[c_void_p, POINTER(c_uint32)], restype=c_int)
# def ssh_options_get_port(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_pcap_file_close(): pass

@libssh(argtypes=[c_void_p])
def ssh_pcap_file_free(): pass

@libssh(restype=c_void_p)
def ssh_pcap_file_new(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_pcap_file_open(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_privatekey_type(): pass

@libssh(argtypes=[c_char_p, POINTER(c_uint8), c_uint32])
def ssh_print_hexa(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_scp_accept_request(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_scp_close(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_scp_deny_request(): pass

@libssh(argtypes=[c_void_p])
def ssh_scp_free(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_scp_init(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_scp_leave_directory(): pass

@libssh(argtypes=[c_void_p, c_int, c_char_p], restype=c_void_p)
def ssh_scp_new(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_scp_pull_request(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_int], restype=c_int)
def ssh_scp_push_directory(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_uint32, c_int], restype=c_int)
def ssh_scp_push_file(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_uint32], restype=c_int)
def ssh_scp_read(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_scp_request_get_filename(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_scp_request_get_permissions(): pass

@libssh(argtypes=[c_void_p], restype=c_uint32)
def ssh_scp_request_get_size(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_scp_request_get_warning(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_uint32], restype=c_int)
def ssh_scp_write(): pass

@libssh(argtypes=[POINTER(c_void_p), POINTER(c_void_p), c_int, c_void_p, c_void_p], restype=c_int)
def ssh_select(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_service_request(): pass

@libssh(argtypes=[c_void_p, c_int])
def ssh_set_blocking(): pass

@libssh(argtypes=[c_void_p])
def ssh_set_fd_except(): pass

@libssh(argtypes=[c_void_p])
def ssh_set_fd_toread(): pass

@libssh(argtypes=[c_void_p])
def ssh_set_fd_towrite(): pass

@libssh(argtypes=[c_void_p])
def ssh_silent_disconnect(): pass

@libssh(argtypes=[c_void_p, c_void_p], restype=c_int)
def ssh_set_pcap_file(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_void_p], restype=c_int)
def ssh_userauth_agent_pubkey(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_userauth_autopubkey(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_char_p], restype=c_int)
def ssh_userauth_kbdint(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_userauth_kbdint_getinstruction(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_userauth_kbdint_getname(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_userauth_kbdint_getnprompts(): pass

@libssh(argtypes=[c_void_p, c_uint32, c_char_p], restype=c_char_p)
def ssh_userauth_kbdint_getprompt(): pass

@libssh(argtypes=[c_void_p, c_uint32, c_char_p], restype=c_int)
def ssh_userauth_kbdint_setanswer(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_userauth_list(): pass

@libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
def ssh_userauth_none(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_int, c_void_p], restype=c_int)
def ssh_userauth_offer_pubkey(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_char_p], restype=c_int)
def ssh_userauth_password(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_void_p, c_void_p], restype=c_int)
def ssh_userauth_pubkey(): pass

@libssh(argtypes=[c_void_p, c_char_p, c_char_p, c_char_p], restype=c_int)
def ssh_userauth_privatekey_file(): pass

@libssh(argtypes=[c_int], restype=c_char_p)
def ssh_version(): pass

@libssh(argtypes=[c_void_p], restype=c_int)
def ssh_write_knownhost(): pass

@libssh(argtypes=[c_void_p])
def ssh_string_burn(): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_string_copy(): pass

@libssh(argtypes=[c_void_p], restype=c_void_p)
def ssh_string_data(): pass

@libssh(argtypes=[c_void_p, c_void_p, c_uint32], restype=c_int)
def ssh_string_fill(): pass

@libssh(argtypes=[c_void_p])
def ssh_string_free(): pass

@libssh(argtypes=[c_char_p], restype=c_void_p)
def ssh_string_from_char(): pass

@libssh(argtypes=[c_void_p], restype=c_uint32)
def ssh_string_len(): pass

@libssh(argtypes=[c_uint32], restype=c_void_p)
def ssh_string_new(): pass

@libssh(argtypes=[c_void_p], restype=c_char_p)
def ssh_string_to_char(): pass

@libssh(argtypes=[c_char_p])
def ssh_string_free_char(): pass

@libssh(argtypes=[c_char_p, c_char_p, c_uint32, c_int, c_int], restype=c_int)
def ssh_getpass(): pass



#
# XXX: skipped from `SSH authentication callback' to `USERAUTH'
#

# @libssh(argtypes=[c_void_p, c_char_p, c_void_p], restype=c_int)
# def ssh_userauth_try_publickey(): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_void_p], restype=c_int)
# def ssh_userauth_publickey(): pass

# @libssh(argtypes=[c_void_p, c_char_p], restype=c_int)
# def ssh_userauth_agent(): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_char_p], restype=c_int)
# def ssh_userauth_publickey_auto(): pass

#
# XXX: skipped from `ssh_userauth_kbdint_getprompt' until end
#









# @libssh(argtypes=[c_void_p], restype=c_char_p)
# def ssh_get_error(session): pass

# @libssh(restype=c_void_p)
# def ssh_new(): pass

# @libssh(argtypes=[c_void_p])
# def ssh_free(session): pass

# @libssh(argtypes=[c_void_p, c_int, c_char_p])
# def ssh_options_set(session, opt_code, opt): pass

# @libssh(argtypes=[c_void_p])
# def ssh_connect(session): pass

# @libssh(argtypes=[c_void_p])
# def ssh_is_server_known(session): pass

# @libssh(argtypes=[c_void_p])
# def ssh_disconnect(session): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_char_p])
# def ssh_userauth_password(session, username, password): pass

# @libssh(argtypes=[c_void_p, c_char_p])
# def ssh_userauth_autopubkey(session, username): pass

# @libssh(argtypes=[c_void_p])
# def ssh_get_fd(session): pass

# @libssh(argtypes=[c_void_p], restype=c_void_p)
# def ssh_channel_new(session): pass

# @libssh(argtypes=[c_void_p])
# def ssh_channel_free(channel): pass

# @libssh(argtypes=[c_void_p])
# def ssh_channel_open_session(channel): pass

# @libssh(argtypes=[c_void_p])
# def ssh_channel_close(channel): pass

# @libssh(argtypes=[c_void_p, c_char_p])
# def ssh_channel_request_exec(channel, command): pass

# @libssh(argtypes=[c_void_p, c_int])
# def ssh_channel_poll(channel, is_stderr): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int, c_int])
# def ssh_channel_read(channel, buffer, bufferlen, is_stderr): pass

# @libssh(argtypes=[c_void_p])
# def ssh_channel_send_eof(channel): pass

# @libssh(argtypes=[c_void_p])
# def ssh_channel_request_pty(channel): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int])
# def ssh_channel_write(channel, data, datalen): pass

# @libssh(argtypes=[c_void_p])
# def ssh_channel_request_shell(channel): pass

# @libssh(argtypes=[c_void_p])
# def ssh_channel_is_open(channel): pass

# @libssh(argtypes=[c_void_p])
# def ssh_channel_is_eof(channel): pass

# @libssh(argtypes=[c_void_p], restype=c_void_p)
# def ssh_scp_new(session): pass

# @libssh(argtypes=[c_void_p])
# def ssh_scp_init(scp_session): pass

# @libssh(argtypes=[c_void_p])
# def ssh_scp_leave_directory(scp_session): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int])
# def ssh_scp_push_directory(scp_ession, path, mode): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int, c_int])
# def ssh_scp_push_file(scp_session, filename, datalen, mode): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int])
# def ssh_scp_write(scp_session, data, datalen): pass

# @libssh(argtypes=[c_void_p])
# def ssh_scp_close(scp_session): pass

# @libssh(argtypes=[c_void_p])
# def ssh_scp_free(scp_session): pass

# @libssh(argtypes=[c_void_p], restype=c_void_p)
# def sftp_new(session): pass

# @libssh(argtypes=[c_void_p])
# def sftp_init(sftp_session): pass

# @libssh(argtypes=[c_void_p])
# def sftp_close(sftp_session): pass

# @libssh(argtypes=[c_void_p])
# def sftp_free(sftp_session): pass

# @libssh(argtypes=[c_void_p])
# def sftp_get_error(sftp_session): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int])
# def sftp_mkdir(sftp_session, path, mode): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int, c_int])
# def sftp_open(sftp_session, filename, access_type, mode): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int])
# def sftp_write(file_handle, data, datalen): pass

# @libssh(argtypes=[c_void_p, c_char_p, c_int])
# def sftp_read(file_handle, buffer, bufferlen): pass
