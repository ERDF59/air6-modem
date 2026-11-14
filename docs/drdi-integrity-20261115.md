# P54 DRDI 摘要更新与构建检查

修改 DRDI 数据后，ROM 内对应的 SHA-256 也必须更新。2026-11-14～15 的 PA 带宽阈值候选遗漏了 group 7、profile 0/1 的两个摘要（索引 448、449），启动时报 `dmmgr_amms_drdi_v2.c:5468`。修正两个既有表项后，640/640 个范围校验通过，候选能启动并联网；504990/PCI722 仍未注册，不能据此宣称 n41 或 CA 已修复。

本次提交只整理摘要修正、离线检查和回归测试。PA 阈值改动、实验镜像、DSP、NV、设备身份、签名材料及其他固件参考不包含在本次提交中。工具保留原生校验代码，不绕过校验，不自动刷机。

## 用法

Python 3，标准库即可。输入必须是含 `md1rom`/`md1drdi` 的未补齐、未签名 MTK 镜像。布局仅针对当前 P54：注册表 ROM 偏移 `0x2150d2c`、目标表 `0x2152b2c`、摘要表 `0x2153f2c`，10×64 项；DRDI 源地址基址 `0x50000000`。先验证两张范围表一致及每项边界，再计算摘要。结构检查不能代替版本/输入 SHA-256 核对，不要套用于其他版本。

```sh
python3 drdi_integrity.py audit candidate-unsigned.img
python3 drdi_integrity.py repair candidate-unsigned.img \
  --output repaired-unsigned.img --report digest-edits.json
python3 drdi_integrity.py audit repaired-unsigned.img
# 只恢复本工具改动的摘要，字节精确还原修正前输入；不会撤销原先的 RF 数据编辑。
python3 drdi_integrity.py restore repaired-unsigned.img \
  --report digest-edits.json --output restored-unsigned.img
python3 -m unittest discover -s tests -p 'test_drdi_integrity.py' -v
```

`audit`：全部匹配退出 0，有不匹配退出 1；格式错误退出 2。`repair`/`restore` 拒绝覆盖已有输出和同名输入；报告记录输入/输出哈希、索引、原值、新值和偏移。校正仅写已有摘要的 32 字节表项，容器长度、DRDI 数据、寄存器范围表及可执行代码保持原样。修改完成后仍须独立签名和设备验证。

## 本机离线复现

| 输入/输出 | 未签名镜像 SHA-256 | 校验结果 |
|---|---|---|
| 已有 P54 one-tx 基线 | `f1fb2e1107d0dbabe45fc48b200a504c41aac1336f1e91b058caef7e75bb4d31` | 640/640 |
| 原 PA 阈值候选 | `1bf6717a3b1e00ab3695ec16e0e91315cbb206fb6650638f5299fad9a18d7cdb` | 638/640；448、449 不匹配 |
| 仅修正摘要后 | `fccbe46a3a02493f33bc4571339d151af67650da1448591281de358940dcb710` | 640/640 |

修正前后只改变两个摘要表项（64 字节范围），重建哈希与此前实测候选一致；用生成的报告恢复后，与原 PA 阈值候选字节完全相同。合成回归测试覆盖过期摘要、重复修正、边界/目标表损坏、截断容器、输出覆盖拒绝和回退完整性，无需厂商镜像。

开源构建 `metadata/emit_unsigned.py` 原先已经重算 640 项摘要；本次把该逻辑集中到同一模块，增加重算后的检查和报告字段。未改原有频段/CA 元数据策略，也不改变有效输入的镜像字节。私有交付脚本在签名前新增只读检查，校验失败即停止。
