# ARCHIVED

> 因 Clash.Meta 内核已经支持这些功能，所以此项目不再更新 XD  
> 推荐使用 [Clash.Meta](https://github.com/MetaCubeX/Clash.Meta) 内核，具有 Clash Premium 相同的功能和额外特性  
> 支持 Meta 内核的桌面客户端：[Clash Verge](https://github.com/zzzgydi/clash-verge)  
> 兼容配置的 iOS 客户端：[Stash](https://stash.wiki) (付费)  
> Clash Meta for iOS 在开发中  

# ClashTool

[ClashTool](https://github.com/xxnuo/ClashTool) 是一个用于生成 Clash 配置文件的工具，它可以根据用户的配置生成符合 Clash 规范的配置文件。

因 [subconverter](https://github.com/tindy2013/subconverter) 对简单的需求过于复杂和缺失一些配置，所以写了这个工具，目前已完成 Python 版本。

## 什么简单的需求？

我只想：

- 聚合多个机场订阅链接和自建线路
- 使用自己的分流规则
- 使用别人写好的分流规则
- 不用手动修改 Clash 难懂的各种 yaml 配置了

ClashTool 现在已经支持这些功能，并且完全兼容 subconverter 原有 list 格式的规则，不需要重写自己原来的规则了。修改也很简单。

并且提供一个开箱即用的配置，只需要修改样例里面的 线路/订阅 部分即可。（自用配置 XD）

## TODO
- [x] 基础需求
- [ ] Web Server 功能

## Python 版本使用方法

1. 电脑上安装有 Python 3.x 和 pip
2. 运行 `git clone https://github.com/xxnuo/ClashTool.git` 下载仓库文件  
    或者手动下载 `ClashTool.py`, `Profile.sample.toml`, `ClashBase.yaml` 文件到同一个 `ClashTool` 文件夹下
4. 进入 `ClashTool` 文件夹，运行 `pip install pyyaml`
5. 复制 `Profile.sample.toml` ，再重命名 `Profile.sample 副本.toml` 为 `Profile.toml`
6. 打开 `Profile.toml`
7. 参考文件 `Profile.sample.toml` 里的说明和示例修改 `Profile.toml` 里的配置项
8. 最后运行 `python ClashTool.py` 会在 `Profile.toml` 同目录下生成 `Output.yaml` 文件
9. 用 Clash 能直接加载 `Output.yaml` 使用

## ROADMAP

- [x] Python 版本
- [ ] Golang 或 Rust 实现单个可执行文件版本
