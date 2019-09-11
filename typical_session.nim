import niup
import libssh
import strformat
import rdstdin
import os
import terminal
import parseutils

proc verify_knownhost(session:ssh_session):int =
    var
      state:ssh_known_hosts_e
      hash:cstring = nil
      srv_pubkey:ssh_key = nil
      hlen:csize #size_t
      hexa:cstring = nil
      rc:int = 0

    rc = ssh_get_server_publickey(session, srv_pubkey)
    if rc < 0:
      return -1

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                addr hash,
                                cast[ptr csize](unsafeAddr(hlen)));
    ssh_key_free(srv_pubkey)
    if rc < 0:
        return -1

    state = ssh_session_is_known_server(session)
    case state:
        of SSH_KNOWN_HOSTS_CHANGED:
            write(stderr, "Host key for server changed: it is now:\n")
            ssh_print_hexa("Public key hash", hash, hlen)
            write(stderr, "For security reasons, connection will be stopped\n")
            ssh_clean_pubkey_hash(addr hash)
            return -1
        of SSH_KNOWN_HOSTS_OTHER:
            write(stderr, "The host key for this server was not found but an other")
            write(stderr, "type of key exists.\n")
            write(stderr, "An attacker might change the default server key to")
            write(stderr, "confuse your client into thinking the key does not exist\n")
            ssh_clean_pubkey_hash(addr hash)
            return -1
        of  SSH_KNOWN_HOSTS_UNKNOWN, SSH_KNOWN_HOSTS_NOT_FOUND:
            if state == SSH_KNOWN_HOSTS_NOT_FOUND:
              write(stderr, "Could not find known host file.\n")
              write(stderr, "If you accept the host key here, the file will be")
              write(stderr, "automatically created.\n")

            hexa = ssh_get_hexa(hash, hlen)
            write(stderr,"The server is unknown. Do you trust the host key?\n")
            ssh_string_free_char(hexa)
            ssh_clean_pubkey_hash(addr hash)
            var buf:string
            discard rdstdin.readLineFromStdin(fmt"Public key hash: {hexa}\n", buf)

            if buf != "yes":
                return -1
            rc = ssh_session_update_known_hosts(session)
            if rc < 0:
                write(stderr, fmt"Error {osErrorMsg(osLastError())}\n")
                return -1
        of SSH_KNOWN_HOSTS_ERROR:
            write(stderr, "Error ssh_get_error(session)")
            ssh_clean_pubkey_hash(addr(hash))
            return -1
        else:
          #SSH_KNOWN_HOSTS_OK
          discard

    ssh_clean_pubkey_hash(addr hash)
    return 0

proc show_remote_processes(session:ssh_session):int =
  const BUFFER_SIZE=256
  var buffer = cast[cstring](newStringOfCap(BUFFER_SIZE))

  let channel = ssh_channel_new(session)
  if channel == nil:
    return SSH_ERROR

  var rc = ssh_channel_open_session(channel)
  if rc != SSH_OK:
    ssh_channel_free(channel)
    return rc

  rc = ssh_channel_request_exec(channel, "ps aux")
  if rc != SSH_OK:
    discard ssh_channel_close(channel)
    ssh_channel_free(channel)
    return rc

  var nbytes = ssh_channel_read(channel, buffer, BUFFER_SIZE, 0)

  while nbytes > 0:
    if writeBuffer(stdout, buffer, nbytes) != nbytes:
      discard ssh_channel_close(channel)
      ssh_channel_free(channel)
      return SSH_ERROR
    nbytes = ssh_channel_read(channel, buffer, BUFFER_SIZE, 0);

  if nbytes < 0:
    discard ssh_channel_close(channel)
    ssh_channel_free(channel)
    return SSH_ERROR

  discard ssh_channel_send_eof(channel)
  discard ssh_channel_close(channel)
  ssh_channel_free(channel)
  return SSH_OK

proc mainProc(host:cstring, port:int) =
  var
    my_ssh_session:ssh_session = nil
  let
    verbosity:cint = SSH_LOG_PROTOCOL

  # Open session and set options
  my_ssh_session = ssh_new()
  if my_ssh_session == nil:
    quit(-1)
  discard ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
  #discard ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, cast[ptr int](unsafeAddr(verbosity)));
  discard ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, cast[ptr int](unsafeAddr(port)));

  # Connect to server
  var rc = ssh_connect(my_ssh_session)
  if rc != SSH_OK:
    write(stderr, fmt"Error connecting to {host}: {ssh_get_error(my_ssh_session)}\n")
    ssh_free(my_ssh_session)
    quit(-1)

  # Verify the server's identity
  # For the source code of verify_knownhost(), check previous example
  if verify_knownhost(my_ssh_session) < 0:
    ssh_disconnect(my_ssh_session)
    ssh_free(my_ssh_session)
    quit(-1)

  # Authenticate ourselves
  rc = ssh_userauth_publickey_auto(my_ssh_session, nil, nil)
  if rc == ord(SSH_AUTH_ERROR):
    write(stderr, fmt"Error authenticating with publickey: {ssh_get_error(my_ssh_session)}\n")
    ssh_disconnect(my_ssh_session)
    ssh_free(my_ssh_session)
    quit(-1)
  elif rc != ord(SSH_AUTH_SUCCESS):
    let password = readPasswordFromStdin(prompt = "password: ")
    rc = ssh_userauth_password(my_ssh_session, nil, password)
    if rc != ord(SSH_AUTH_SUCCESS):
      write(stderr, fmt"Error authenticating with password: {ssh_get_error(my_ssh_session)}\n")
      ssh_disconnect(my_ssh_session)
      ssh_free(my_ssh_session)
      quit(-1)

  #
  # DO SOMETHING
  #
  discard show_remote_processes(my_ssh_session)
  #

  ssh_disconnect(my_ssh_session)

  ssh_free(my_ssh_session)

if isMainModule:
  var
    port = 22
    host = ""

  if paramCount() == 0:
    echo "Usage: typical_session <host> [<port>]"
    quit(1)
  elif paramCount() == 1:
    host = paramStr(1)
  elif paramCount() == 2:
    host = paramStr(1)
    discard parseInt(paramStr(2), port)

  mainProc(host, port)
