# OpenSSL-Lab
Understand RSA in OpenSSL

## RSA Key Check Tool
Install the requirement library with this command.
```bash
$ pip install -r requirements.txt
```

The program runs with system arguments. The running command format is
```bash
Usage: python3 key_check.py <private_key_file> [<public_key_file>]

The public key file argument is optional.
```

An example command.
```bash
$ python3 key_check.py priv.pem pub.pem
```
