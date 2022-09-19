# clash-subscription-updater

在开始前，请确保在[官方文档](https://github.com/Dreamacro/clash/wiki)的帮助下成功运行了clash。

该项目用以解决[#306](https://github.com/Dreamacro/clash/issues/306)中提出的问题。

或许 [Rule Provider](https://lancellc.gitbook.io/clash/clash-config-file/rule-provider) 就能满足当前需求。

### 引用摘自 Rule Provider 中 [behavior](https://lancellc.gitbook.io/clash/clash-config-file/rule-provider#behavior) 部分

> `classical` type does't support these following options:
> 1. `match` type
> 2. Policies after the matcher

官方文档中明确指出`payload`并非完整的`rules`，在不拆分规则的情况下，无法将其分离出配置文件，这种方式对于订阅用户来说反而增加了耦合性，毕竟还要修改`config.yaml`，更新起来也极不方便。虽然订阅中的规则基本不会发生变动，但并不能保证供应商不会去更新。

大部分市面上的Clash订阅都包含了完整的信息，但每个用户基本上都有一套自己的配置，多数情况下只会[引用](https://lancellc.gitbook.io/clash/clash-config-file/proxy-provider)订阅里的节点再配合自己的规则使用，更有甚者表示这些规则我都要。

此项目就是用来实现这些功能的，与其它同类项目不一样的地方在于，这里采用`script`模式，脚本由`updater.py`基于`script.py`生成，尽量保证不去修改`config.yaml`。

由于`script`模式所提供的接口并不多，脚本不得不重新实现`match`逻辑，为了确保一致性，代码是从go迁移过来的。

需要注意的是，脚本语言并非py而是[starlark](https://github.com/bazelbuild/starlark)，starlark是py的子集，py对下兼容，`updater.py`中引用了`script.py`。

## Getting Started

1\. Download `script.py` and `updater.py` to `/etc/clash`

2\. Modify `config.yaml`

```yaml
# The updater will reload the configuration using the RESTful API
external-controller: :9090
mode: Script

# https://github.com/Dreamacro/clash/releases/tag/premium
script:
    path: script.0.py
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
The updater checks for the existence of rule-policies in config.yaml and uses default_policies when they do not exist.
The clash hosting address should follow the [URL Scheme](https://docs.cfw.lbyczf.com/contents/urlscheme.html).
Try `python3 updater.py -h` for more information.

Launch updater on system startup with:

    $ systemctl enable updater

Launch updater immediately with:

    $ systemctl start updater

You can change the service name to your needs.
