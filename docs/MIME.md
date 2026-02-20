# Cobalt File Format Registration

This document defines the standard file association properties for Cobalt (CBC) artifacts.

## File Signatures (Magic Bytes)

All Cobalt v0.1 artifacts start with the 64-byte Bootstrap Segment. The first 4 bytes are fixed:

| Offset | Hex | ASCII | Description |
| :--- | :--- | :--- | :--- |
| 0x00 | `43 42 43 31` | `CBC1` | Format identifier + Version 1 |

## MIME Type

* **Type**: `application/x-cobalt`
* **Extensions**: `.cbc`
* **Uniform Type Identifier (UTI)**: `io.cobalt.archive`

## System Integration

### Linux (`file` command)

Create `~/.magic` or append to `/etc/magic`:

```magic
0   string  CBC1      Cobalt Context-Bound Container (v1)
>4  byte    x         \b, Mode: 0x%x
>12 lelong  x         \b, Block Size: %d
```

### Linux (FreeDesktop MIME)

Create `~/.local/share/mime/packages/cobalt.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-cobalt">
    <comment>Cobalt Artifact</comment>
    <glob pattern="*.cbc"/>
    <magic priority="50">
      <match type="string" value="CBC1" offset="0"/>
    </magic>
  </mime-type>
</mime-info>
```

Update database: `update-mime-database ~/.local/share/mime`

### macOS (UTI)

* **Identifier**: `io.cobalt.archive`
* **Conforms To**: `public.data`, `public.archive`
* **Tag Specification**: `public.filename-extension` = `cbc`
