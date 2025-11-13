
# Tlv

Tag-length-value protocol implementation

## Description

Tlv is a simple and configurable coding protocol. It can be used to frame bytes to robustly
communicate them as messages over a network. Tlv guarantees that messages would not unknowingly be
cut off in the middle of receiving due to read batch artifacts.

Zig Tlv uses the standard reader/writer interfaces, so it's compatible with e.g. socket streams.

**Example using a fixed-width tag-length header of 32 bits each**:

```zig
const Tag = enum(u32) {
    chown,
    chmod,
    chroot,
    _
};

var outgoing = std.ArrayList(u8).init(std.testing.allocator);
defer outgoing.deinit();

// define the protocol
const Protocol = Tlv(Tag, .{ .fixed_little = u32 });

// write to a stream
try Protocol.write(.chroot, "/foo", outgoing.writer());

try std.testing.expectEqualSlices(u8, &.{
    0x02, 0x00, 0x00, 0x00, // tag: chroot (2)
    0x04, 0x00, 0x00, 0x00, // length: 4
    '/', 'f', 'o', 'o'      // value: /foo
}, outgoing.items);

var incoming = std.io.fixedBufferStream(outgoing.items);

// read from a stream
const message = try Protocol.read(std.testing.allocator, incoming.reader());
defer message.deinit(std.testing.allocator);

try std.testing.expectEqual(Tag.chroot, message.tag);
try std.testing.expectEqual(@as(u32, 4), message.length);
try std.testing.expectEqualSlices(u8, "/foo", message.value);
try std.testing.expect(message.is_complete());
```

**Example using [ULEB128](https://en.wikipedia.org/wiki/LEB128) header encoding**:

```zig
const Tag = enum(usize) { _ };

var outgoing = std.ArrayList(u8).init(std.testing.allocator);
defer outgoing.deinit();

// define the protocol
const Protocol = Tlv(Tag, .uleb128);

// write to a stream
try Protocol.write(@enumFromInt(624485), "Hello world!", outgoing.writer());

try std.testing.expectEqualSlices(u8, &.{
    0xE5, 0x8E, 0x26, // tag: 624485
    0x0C, // length: 12
    'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!' // value: Hello world!
}, outgoing.items);

var incoming = std.io.fixedBufferStream(outgoing.items);

// read from a stream
const message = try Protocol.read(std.testing.allocator, incoming.reader());
defer message.deinit(std.testing.allocator);

try std.testing.expectEqual(@as(Tag, @enumFromInt(624485)), message.tag);
try std.testing.expectEqual(@as(u32, 12), message.length);
try std.testing.expectEqualSlices(u8, "Hello world!", message.value);
try std.testing.expect(message.is_complete());
```

## Installation

`zig fetch --save git+https://github.com/QSmally/Tlv`

```zig
const tlv = b.dependency("tlv", .{ ... });
exec.root_module.addImport("tlv", tlv.module("tlv"));
// ...
```

Commit HEAD compiled with Zig `0.14.1`.
