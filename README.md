# GenericPotato
### A modified version of SweetPotato by @_EthicalChaos_ to support impersonating authentication over HTTP and/or named pipes. This allows for local privilege escalation from SSRF and/or file writes.
### For background and explanation see https://micahvandeusen.com/the-power-of-seimpersonation/

```
GenericPotato by @micahvandeusen
  Modified from SweetPotato by @_EthicalChaos_

  -m, --method=VALUE         Auto,User,Thread (default Auto)
  -p, --prog=VALUE           Program to launch (default cmd.exe)
  -a, --args=VALUE           Arguments for program (default null)
  -e, --exploit=VALUE        Exploit mode [HTTP|NamedPipe(default)]
  -l, --port=VALUE           HTTP port to listen on (default 8888)
  -i, --host=VALUE           HTTP host to listen on (default 127.0.0.1)
  -h, --help                 Display this help
```