
# Tlv

Tag-length-value protocol implementation

## Description

Tlv is a simple and configurable coding protocol. It can be used to frame bytes to robustly
communicate them as messages over a network, for example. Tlv guarantees that received messages are
not cut off in the middle of receiving due to read batch artifacts.

Zig Tlv uses the standard reader/writer interfaces, so it's compatible with e.g. sockets.

```zig
const tlv = @import("tlv");

const Tag = enum(u32) {
    chown,
    chmod,
    chroot,
    _
};

// define the protocol
const TlvInstance = tlv.Tlv(Tag, .{ .fixed_little = u32 });

// write to a stream
var protocol = std.ArrayList(u8).init(std.testing.allocator);
defer protocol.deinit();
try TlvInstance.write(.chroot, "/foo", protocol.writer());

// read from the stream
var buffer = std.io.fixedBufferStream(protocol.items);
const message = try TlvInstance.read(std.testing.allocator, buffer.reader());
defer message.deinit(std.testing.allocator);

try std.testing.expectEqual(Tag.chroot, message.tag);
try std.testing.expectEqual(@as(u32, 4), message.length);
try std.testing.expectEqualSlices(u8, "/foo", message.value);
try std.testing.expect(message.is_complete());
```

## Installation

`zig fetch --save git+https://github.com/QSmally/Tlv`

```zig
const tlv = b.dependency("tlv", .{ ... });
exec.root_module.addImport("tlv", tinytokeniser.module("tlv"));
// ...
```

Commit HEAD compiled with Zig `0.14.1`.
