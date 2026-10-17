# CLIChat

终端聊天原型：Rust、iroh、OpenMLS 和 SQLCipher。支持一对一会话、最多 50 人的小群、客户端互助缓存、图片及音视频文件。消息与媒体均从发送时起 72 小时到期。

## 安装发行版

从 [Releases](https://github.com/quitlunlee/Quirtchat/releases) 下载对应压缩包和它的 `.sha256` 文件。私有仓库需要先登录有访问权限的 GitHub 账号。发行版不需要安装 Rust、OpenSSL 或 SQLCipher；终端内音视频播放可另行安装 `mpv`。

| 系统与处理器 | 压缩包文件名中的平台 |
| --- | --- |
| Windows x64 | `x86_64-pc-windows-msvc.zip` |
| Linux x64 | `x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin.tar.gz` |
| macOS Intel | `x86_64-apple-darwin.tar.gz` |

完整文件名形如 `clichat-0.1.0-x86_64-pc-windows-msvc.zip`。Windows 目标为 Windows 10 及以上；macOS 构建目标为 11.0 及以上，自动运行检查使用 macOS 15；Linux 使用静态 musl 构建。各平台可用性以相应版本的成功 CI 和实机验证为准。

Windows 在 PowerShell 中校验下载文件，再解压并运行：

```powershell
$archive = 'clichat-0.1.0-x86_64-pc-windows-msvc.zip'
$expected = ((Get-Content "$archive.sha256" -Raw) -split '\s+')[0]
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne $expected) { throw '校验失败' }
Expand-Archive -LiteralPath $archive -DestinationPath .
Set-Location clichat-0.1.0-x86_64-pc-windows-msvc
.\clichat.exe init --name Alice
.\clichat.exe chat
```

Linux 使用 `sha256sum -c 文件名.sha256`，macOS 使用 `shasum -a 256 -c 文件名.sha256` 校验。解压对应 `.tar.gz`，在解压出的目录执行：

```sh
chmod +x clichat
./clichat init --name Alice
./clichat chat
```

首次 `init` 会创建本地身份并设置加密数据库密码。如需在任意目录直接执行 `clichat`，可将可执行文件放入 PATH；Linux/macOS 可用 `install -m 755 clichat "$HOME/.local/bin/clichat"`（先创建目录，并将其加入 PATH）。

当前没有 Windows 代码签名证书或 Apple Developer ID 公证；macOS 仅进行 ad-hoc 签名，系统可能要求额外确认。SHA-256 用于核对文件完整性，不能替代可信发布来源。压缩包内附有安装说明、版本清单及第三方许可。

## 开始聊天

不传子命令也会进入主菜单，主菜单只有居中的 logo。所有操作都从 `:` 进入：背景虚化，出现搜索框。直接输入即可过滤，`#` 开头搜索会话，`@` 开头搜索联系人，其余匹配命令。`↑` / `↓` 或 `Tab` 选择，`Enter` 执行，`Esc` 退出。选中会话后进入聊天界面，聊天界面里按 `Esc`（普通模式）返回主菜单。

- `invite`：打开文件管理器选择保存位置，文件名默认是 `<你的名字>.invite`，不会覆盖已有文件。保存后显示你自己的 randomart 卡片。
- `add`：打开文件管理器选择对方的 `.invite` 文件；也可以直接粘贴 `clichat1:` 开头的好友码，或输入 `add 路径`。解码并验签通过后先显示对方的 randomart 卡片，按 `Enter` 才加入，`Esc` 取消。
- `proxy`：输入 `host:port`、完整的 HTTP/HTTPS 地址或 `off`；右侧显示当前值，下次启动生效。

**文件管理器**：`j` / `k` 或 `↓` / `↑` 移动，`l` / `Enter` 进入文件夹或选中文件，`h` / `Backspace` 返回上级（在盘符根目录再按一次会列出所有盘符），`gg` / `G` 跳到顶部 / 底部，`~` 回到起始目录，`.` 显示或隐藏隐藏文件和非 `.invite` 文件，`Tab` 在列表和文件名之间切换，`Esc` 取消。保存时 Save 从“文档”目录开始，Add 从“下载”目录开始，本次运行内会记住上次所在的目录。超过 256 KiB 的文件不能选中。

**好友码与 randomart**：好友码是一个已签名的邀请文件，里面有 MLS KeyPackage 和网络票据，不能只用一个哈希代替。文件开头附有一张由 `SHA-256(身份)` 生成的 randomart 卡片，最后一行仍是 `clichat1:…` 代码。卡片只用于肉眼核对，导入时一律根据已验签的身份重新计算，文件里画的图不会被信任；旧的单行邀请文件仍然可以导入。`status`、`contact list`、`contact add` 也会打印同样的卡片。

面板里的命令都对应原有的斜杠命令，也可以在聊天输入框里直接输入：

```text
/invite alice.invite        导出联系邀请（不会覆盖已有文件）
/add bob.invite             导入对方的邀请文件
/dm Bob                     建立或打开一对一会话
/group Friends Bob Carol    创建群聊
/use Friends                切换会话
/add-member Dave            为当前群添加成员
/kick Dave                  从当前群移除成员
/recover                    请求群主恢复当前群的密钥状态
/attach C:\Media\photo.png  发送不超过 20 MiB 的图片或音视频文件
/open                       下载并预览当前会话最新附件
/open MESSAGE_PREFIX        下载并预览指定消息的附件
/download MESSAGE_PREFIX    只下载到加密缓存，稍后再预览
/proxy host:port|off        设置 HTTP/HTTPS 代理，下次启动生效
/motion off                 关闭动画
/quit                       退出
```

聊天界面默认处于 Vim 普通模式，按 `i` 输入，Enter 发送；Ctrl+Enter 换行。不支持该组合键的终端可以使用 Alt+Enter。邀请也可直接作为 `/add` 的参数。邀请包含加入联系的授权，请只交给预期联系人，并通过另一可信渠道核对身份指纹。添加成员时，对方需要在线以签发单次使用的 MLS KeyPackage。

程序只有在运行时才收发和参与缓存。退出终端后希望保持在线，可单独使用 `clichat serve`；它与交互界面不能同时打开同一配置目录。

## 终端界面与快捷键

界面为纯黑背景。输入框和命令面板使用同一种玻璃质感：略亮的深色底、顶边高光、青紫渐变细边框和细点阵纹理。终端字符不能设置窗口透明度；如需真正的透明或亚克力，请在终端本身（例如 Windows Terminal）中设置，应用只提供视觉上的玻璃效果。需要 24 位真彩色终端。

界面上没有说明文字：聊天顶部只有会话名和连接圆点（队列大于 0 时显示数量）；他人消息显示名字和右侧的剩余时间，自己的消息用左侧青色竖线区分；`●` 表示已缓存，`○` 表示排队中。光标形状表示模式：块为普通模式，竖线为输入模式。

动画：启动时 logo 逐字解码并定期扫光；`:` 打开时背景虚化；发送成功后粒子从输入框升起；消息到期时先移除正文，再散成无内容的细粒子向上飘散。粒子最多 160 颗，只记录消息 ID、截止时间和矩形，不保存内容。可用 `/motion off` 或环境变量 `CLICHAT_REDUCED_MOTION=1` 关闭全部动画。

| 按键 | 行为 |
| --- | --- |
| `i` / `a` / `I` / `A` | 在光标前、后、行首、行尾进入输入模式 |
| `Esc` | 返回普通模式；普通模式下返回主菜单；关闭面板或预览 |
| `Enter` | 发送草稿，返回普通模式 |
| `Ctrl+Enter` / `Alt+Enter` | 插入换行 |
| `h` / `l`、`w` / `b`、`0` / `$` | 编辑光标移动 |
| `x` / `dd` | 删除字符 / 当前行 |
| `yy` / `yw` / `y$` / `y0` | 复制当前行 / 单词 / 到行尾 / 到行首 |
| `p` / `P` | 从内部寄存器粘贴到后方 / 前方 |
| `u` / `Ctrl+r` | 撤销 / 重做草稿编辑 |
| `j` / `k`、`gg` / `G` | 滚动聊天记录、跳至顶部 / 底部 |
| `Tab` / `Shift+Tab` | 聊天中切换会话 |
| `:` | 打开命令面板（主菜单或聊天的普通模式） |
| `/` | 在输入框中输入斜杠命令 |
| `Ctrl+c` | 清空草稿；草稿为空时退出 |

复制、撤销和重做只作用于当前草稿；发送后清空内部寄存器与撤销记录。系统粘贴经过控制字符过滤，不会自动执行或发送。第一版不实现宏、外部编辑器、文件缓冲区或完整 Vim 语言。

## 图片、音频和视频

单文件上限 **20 MiB**。支持 PNG、JPEG、GIF、WebP；MP3、WAV、FLAC、Ogg/Opus、M4A；MP4、MOV、WebM。这里只提供文件发送、接收、预览和播放，不包含实时通话或录音。

文件以独立随机密钥进行 XChaCha20-Poly1305 分块加密，块大小 64 KiB。文件名、类型、大小、完整性摘要、解密密钥与取回权限放在 MLS 加密消息内。每块认证绑定文件 ID、序号、大小、块数和原始到期时间，下载完成后验证完整 SHA-256。断点进度与密文存入加密数据库。

接收方看到附件卡片后通过 `/open` 按需下载。发送者将一份密文上传到最多三个已分配的缓存节点，不向群内每位成员主动复制大文件。发送者和这些节点都不可用时，下载等待重试。刚发送的附件不代表离线副本已全部上传，保持 `chat` 或 `serve` 运行可继续传输。

图片以内置真彩半格字符预览，GIF/WebP 只显示静态帧。解码有尺寸与内存限制，过大的像素尺寸会拒绝预览；传输限制与解码限制不同。音视频优先调用 PATH 中的 `mpv`：视频使用终端 `tct` 输出，音频直接播放。按 `q` 停止播放并回到聊天；到期时客户端停止它启动的播放器并清理临时文件。没有 `mpv` 时按提示再按 `O` 用系统应用打开。

接收文件的密文缓存、聊天里的解密密钥和应用预览在原消息发送后 72 小时到期。发送者自己选择的原始文件不会被删除。外部应用可能自行留存副本，Windows 上占用中的文件删除也可能延迟重试；不能承诺替其他软件删除缓存。预览临时文件使用随机名称和到期时间，程序重启时清理过期残留。

## 命令行操作

```sh
clichat invite --output alice.invite
clichat contact add bob.invite
clichat contact list
clichat group create Friends --member Bob --member Carol
clichat group add Friends Dave
clichat group remove Friends Dave
clichat group recover Friends
clichat group list
clichat send Friends "Hello"
clichat attach Friends "C:\Media\clip.mp4" --caption "A short clip"
clichat history Friends
clichat status
```

名字有歧义时使用完整身份或会话 ID。可通过 `--data-dir PATH` 指定独立配置目录。自动化环境可使用 `--password-file PATH` 读取受保护的密码文件，密码不放入命令行参数；不要共享该文件。

单次命令会短暂尝试联网后退出。要持续重试、接收入群确认和投递消息，使用 `chat` 或 `serve`。

## 网络与代理

```sh
clichat config proxy http://127.0.0.1:7890
clichat config proxy off
clichat config cache off
clichat config cache on
```

配置在下一次启动生效。`cache` 控制为其他用户缓存密文，默认开启。代理支持 HTTP/HTTPS CONNECT，不能直接填写 SOCKS5 地址。也可以在命令面板的 `proxy` 中设置。

启用代理后，客户端关闭直接 UDP、端口映射、DNS/Pkarr 地址发现，仅经代理连接 iroh relay；代理失效时保持离线，不自动退回直连。建议填写本地 IP 代理地址。若填写远程代理域名，连接代理本身仍可能使用系统 DNS。

普通模式使用 iroh 公共 relay 帮助连接，并尽量升级为直连。公共 relay 不保存聊天消息，也没有本应用可依赖的服务保证。客户端通过邀请和节点交换逐步发现彼此；不存在预先部署的 CLIChat 全网缓存集群。

## 离线投递与过期

- 每位用户向最多三个事先协商的客户端邮箱存放密文；读取和写入使用不同权限。
- 默认自动参与缓存，第三方文字与媒体共享 256 MiB 逻辑缓存上限，单邮箱 32 MiB；自己的媒体缓存另有 256 MiB 上限。应用负载总限速 256 KiB/s，最多八个并发请求。
- 缓存确认只代表节点已持久化，不能等同于收件人收到。所有副本离线、拒绝服务或丢失时只能等待，不能保证最终送达。
- 消息在创建时确定原始发送时间与到期时间。本地队列、缓存、聊天记录、重试和历史补发共享同一到期时间。
- 已读消息也在 72 小时后删除。离线程序下次启动先清理再展示；运行中定期清理。此规则不能约束修改过的客户端、截图或用户自行保存的副本。
- 旧邮箱轮换后保留读取能力以补收消息。不能确认安全回收时保守保留，最多十二个本地邮箱记录。

## 密钥与本地状态

第一版使用标准 MLS 和 OpenMLS，没有直接集成实验性的 diMLS 实现。群主是唯一 MLS Commit 协调者。群主离线时管理及成员密钥更新等待，已同步的成员仍可聊天。双人会话由创建者承担协调职责。客户端每天尝试更新密钥；群主按顺序提交成员的更新提案。

控制记录独立于聊天 TTL，每群最多保留约 32 MiB。成员上线先尝试补齐连续记录；记录缺失时由群主验证当前成员资格并执行 fresh KeyPackage 恢复。不会因长期离线自动踢人。恢复后可从群主补收仍未过期且带原发送者签名的历史；群主没有保存的内容无法凭空恢复。

踢人对已处理新 Commit 的发送者生效。网络分区中尚未同步的成员仍可能使用旧状态；已知被踢成员随后到达的旧消息会拒收。群主永久丢失状态时需要重建群，不会自动选举或允许旧邀请恢复被踢成员。

数据库使用 SQLCipher，密码通过 Argon2id 派生密钥。`profile.db.salt` 是非秘密但必需的盐，必须与数据库一起保留。不要复制运行中的配置目录到多台设备并同时使用；这会破坏单设备和单写入者假设。第一版不提供聊天历史备份或多设备同步。

消息、控制记录和 MLS 状态在同一个数据库事务内提交，成功后才确认接收；崩溃重试使用已经持久化的原始消息。

## 从源码构建与发布

源码构建需要 Rust 1.99.1、平台 C 编译环境和 Perl。SQLCipher/OpenSSL 随源码编译，不依赖用户预装的数据库。Windows 使用系统 Rust、MSVC Build Tools 和原生 Windows Perl：

```powershell
.\scripts\system.ps1 build --release --locked
.\scripts\system.ps1 test --locked --all-targets
```

该脚本会加载 Visual Studio 环境，并将原生依赖放在临时目录的 ASCII 路径下。`scripts/dev.ps1` 是本工作区便携 GNU 环境的备用入口。Linux/macOS 可以直接构建：

```sh
cargo build --release --locked
cargo test --locked --all-targets
cargo test --locked fifty_members -- --ignored
```

`.github/workflows/ci.yml` 在五个原生 runner 上检查格式、Clippy、测试、可执行文件依赖和加密配置读写。Linux 发行包使用 musl 工具链构建静态二进制；Windows 静态链接 CRT；macOS 检查最低系统版本、系统动态库及签名。

上传源码后，在 GitHub Actions 中手动运行 **Build release archives**，可下载完整的 `release-bundle`。它包含五个安装包、各包 `.sha256` 和汇总 `SHA256SUMS`。只有全部平台通过才会生成完整聚合包。

创建正式版本时，先更新 `Cargo.toml`、`Cargo.lock` 和文档中的版本并提交，再推送与版本一致的 `v` 标签，例如 `v0.1.0`。标签工作流成功后会创建包含全部附件的草稿 Release，供检查后发布。私有仓库的 Release 保持在仓库访问权限内；此流程不改变仓库可见性。不要移动已分发版本的标签。

`scripts/release.py` 使用 Python 3.11 及以上，只将指定的可执行文件、说明和许可证加入包中；不会打包聊天配置、邀请、密码或构建工具。每个平台都必须用真实构建产物和该目标的 Cargo metadata，禁止给同一个二进制改名充当其他平台的版本。

## 当前边界

这是可审查的原型实现，尚未经过独立安全审计。普通直连会暴露 IP，缓存节点也能观察连接、邮箱及流量信息；本项目不提供流量匿名性或抗 Sybil 的公开存储可用性保证。

有明确资源限制：每条文字最多 16 KiB、每个配置最多 128 个会话、512 个联系人；MLS 保留最多 256 个旧 epoch、每发送者 1,024 代乱序密钥，最大前进 4,096 代。超过窗口时可能需要群主协助恢复。密码学状态持续存在不等于聊天内容长期保存，也不能将逻辑删除视作磁盘取证不可恢复承诺。

三平台 CI 配置位于 `.github/workflows/ci.yml`。本地 Windows 测试结果不能替代实际 Linux/macOS CI 或跨公网、多 NAT 环境测试。

当前本机验证：Windows 全 targets 112 项测试通过、2 项跳过，Clippy 的 `-D warnings` 检查通过；此前另行运行的 50 人完整收发测试通过。覆盖真实 localhost 三节点离线缓存与媒体断点续传、SQLCipher 崩溃恢复、错误权限与篡改、72 小时边界、Vim 操作、窄屏布局、邀请卡片和图片预览。系统 Rust/MSVC 与便携 GNU 均已构建测试；mpv 实际播放和各平台外部播放器行为仍需在相应终端中验证。

## 结构

`model` 定义协议和有效期；`crypto` 封装标准 MLS；`storage` / `media_store` 管理加密数据库和邮箱；`transport` 提供有界 iroh 请求；`app`、`ticker`、`rekey` 实现会话、调度与密钥更新；`media` / `media_app` 加密和传输附件；`ui`、`editor`、`ui_effects`、`ui_theme`、`ui_logo`、`ui_palette`、`ui_files`、`ui_card`、`media_view` 提供终端交互、动画和预览。

协议仍是 `0.1` 原型，不承诺跨版本配置或线协议兼容。不要将测试配置用于敏感通信。
