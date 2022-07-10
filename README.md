# clash-hosting-updater

Before start, make sure you have successfully run clash with the help of the [documentation](https://github.com/Dreamacro/clash/wiki).

UDP related settings are not supported, all UDP connections are handled by default.

### What is this?

When the subscription is given a full configuration file, rule-providers will be useless, even if the `rules` are changed to `payload`, `classical` can not replace rules. Without modifying the premise of `config.yaml`, you can only use script, subject to starlark limited functionality, this updater was born.

## Getting Started

1\. Download `script.py` and `updater.py` to `/etc/clash`

2\. Modify `config.yaml`

```yaml
# The updater will reload the configuration using the RESTful API
external-controller: :9090
mode: Script

# https://github.com/Dreamacro/clash/releases/tag/premium
script:
    path: ./script.rules.py
```

3\. Configure [clash systemd](https://github.com/Dreamacro/clash/wiki/clash-on-a-daemon#systemd)

```ini
[Unit]
Description=Clash daemon, A rule-based proxy in Go.
After=network.target

[Service]
Type=simple
Restart=always
ExecStart=/opt/gopath/bin/clash -d /etc/clash
ExecReload=/bin/curl -X 'PUT' 'http://127.0.0.1:9090/configs?force=true'  \
                     -d '{"path": "/etc/clash/config.yaml"}'

[Install]
WantedBy=multi-user.target
```

4\. Install python3, minimum supported 3.6.8

5\. Create the systemd configuration file at `/etc/systemd/system/updater.service`

```ini
[Unit]
Description=Clash hosting updater daemon, A rule-based script builder in Python.
Requires=clash.service

[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/python3 -u /etc/clash/updater.py default_policies url
WorkingDirectory=/etc/clash
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=process

[Install]
WantedBy=multi-user.target
```

`updater.py` takes two parameters, in order, `default_policies` and `url`.
The updater checks for the existence of rule-policies in `config.yaml`(proxy-groups only) and uses `default_policies` when they do not exist.
The clash hosting address should follow the [URL Scheme](https://docs.cfw.lbyczf.com/contents/urlscheme.html).
Try `python3 updater.py -h` for more information.

Launch updater on system startup with:

    $ systemctl enable updater

Launch updater immediately with:

    $ systemctl start updater

You can change the service name to your needs.
