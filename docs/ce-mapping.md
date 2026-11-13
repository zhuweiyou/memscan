# Cheat Engine 对齐说明

本项目搜索内核以 Cheat Engine 的 `Cheat Engine/memscan.pas` 与其类型头
`commontypedefs.pas` 为准进行实现。下面记录关键语义来源与落地位置，便于后续继续对齐。

## 1. 枚举

`commontypedefs.pas`：

```
TScanOption = (soUnknownValue, soExactValue, soValueBetween, soBiggerThan, soSmallerThan,
               soIncreasedValue, soIncreasedValueBy, soDecreasedValue, soDecreasedValueBy,
               soChanged, soUnchanged, soForgot, soCustom);
TScanType   = (stNewScan, stFirstScan, stNextScan);
TRoundingType = (rtRounded, rtExtremerounded, rtTruncated);
TVariableType = (vtByte, vtWord, vtDword, vtQword, vtSingle, vtDouble, vtString,
                 vtUnicodeString, vtByteArray, vtBinary, vtAll, ...);
TFastScanMethod = (fsmNotAligned, fsmAligned, fsmLastDigits);
Tscanregionpreference = (scanDontCare, scanExclude, scanInclude);
```

落地：`memscan/src/types.rs` 的 `ScanOption` / `ScanType` / `RoundingType` /
`VariableType` / `FastScanMethod` / `TriState`。名称与语义保持一一对应。

## 2. 内存区域枚举与过滤

`memscan.pas` 中区域有效性判定（约 6917-6960 行 `IsAddressValid`，以及约
7085-7210 行 `GetMemoryRegions` 的 `VirtualQueryEx` 循环）：

```
validRegion := (mbi.State = MEM_COMMIT)
           and (BaseAddress < stopaddress)
           and ((mbi.Protect and PAGE_GUARD) = 0)
           and ((mbi.Protect and PAGE_NOACCESS) = 0)
           and private/image/mapped 类型开关
           and 非 PAGE_NOCACHE / PAGE_WRITECOMBINE;

isWritable   := PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
isExecutable := PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
isCopyOnWrite:= PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY
再由 scanWritable/scanExecutable/scanCopyOnWrite 的 Include/Exclude/DontCare 决定。
```

落地：`memscan/src/region.rs` 的 `RegionFilter::matches` + `MemoryRegion::is_*`，
以及 `memscan/src/backend.rs::Process::regions`：区域列表由 `proc-maps` 提供，再裁剪到
`[start, stop)` 并套用相同的过滤条件。

## 3. 分块读取 + 边界重叠 + 部分读取重试

`memscan.pas` 的 `TScanner.firstscan`（约 5760-5900 行）：把每个区域按 `buffersize`
分块 `ReadProcessMemory`；跨块保留 `variablesize-1` 字节重叠以命中跨块的值；当
`actualread <> _size` 时从 `currentbase+previousActualRead` 续读补齐。

落地：`scanner.rs::build_tasks` 用 `overlap = value_len-1` 计算 `read_len`；
`scan_chunk` 只接受起点 `< scan_len` 的命中避免重复；`backend.rs::read_memory`
基于 `process-memory`，在全量读取失败时退化为逐页读取（`read_pagewise`）。

## 4. 首次扫描 / 再次扫描

- 首次扫描：遍历所有满足过滤的区域，产物是「地址 + 旧值字节」列表。
- 再次扫描：CE 对已命中地址按页（4 KiB）成组读取后再比较（`memscan.pas` 约 4448 行注释），
  支持 changed/unchanged/increased/decreased/increasedby/decreasedby/exact/between/bigger/smaller。

落地：

- `result.rs::FoundList` 用「地址 + arena(offset,len)」紧凑存旧值，避免每命中一次堆分配。
- `scanner.rs::MemScan::first_scan` / `next_scan`；再次扫描用 4 KiB 页缓存（`page_base`），
  每页最多读一次。
- 比较语义在 `scanner.rs::numeric_first_match` 与 `NextComparison::keep`。

## 5. FastScan 对齐

`TFastScanMethod` / `fastscanalignment` / `fastscandigitcount`。CE 默认按值类型对齐
（例如 dword 4 字节对齐）。本项目 `FirstScanRequest::align`：`None` 时整数用类型自然
对齐（`VariableType::natural_alignment`），字符串/AOB 用 1；可将 `FirstScanRequest::align` 设为 `Some(1)` 逐字节扫描。

## 6. AOB / 字符串匹配

- CE `vtByteArray` 支持 `??` 通配；本项目扩展为 nibble 级 `5?` / `?A`。
- CE `vtString` 为字节串子串匹配，`vtUnicodeString` 为 UTF-16LE；本项目统一编译成
  「字节 + 位掩码」模式，UTF-16LE 即按码元展开为 little-endian 字节；大小写不敏感
  通过 ASCII 折叠实现（对 UTF-16LE 的低字节同样有效）。

落地：`pattern.rs::AobPattern`：

- 无通配符走 `memchr::memmem`（SIMD）。
- 有通配符时选一个全已知字节做锚点，用 `memchr` 找候选再逐字节校验；无锚点则暴力窗口。
- 支持重叠匹配（与 CE 逐字节扫描一致）。

## 7. 参考文件

- `Cheat Engine/memscan.pas`
- `Cheat Engine/commontypedefs.pas`
- `Cheat Engine/ProcessHandlerUnit.pas`
