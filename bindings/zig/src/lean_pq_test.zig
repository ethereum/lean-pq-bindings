const std = @import("std");
const lpq = @import("lean_pq");

const message: lpq.Message = [_]u8{0x42} ** 32;
const other_message: lpq.Message = [_]u8{0x43} ** 32;
const kept_height = 4;

test "leanXMSS signs and verifies" {
    var key = try lpq.XmssSecretKey.fromSeed([_]u8{1} ** 32);
    defer key.deinit();
    const public_key = try key.publicKey();
    try key.prepare(7);
    const signature = try key.sign(message, 7);

    try lpq.xmssVerify(public_key, message, &signature);
    try std.testing.expectError(error.InvalidSignature, lpq.xmssVerify(public_key, other_message, &signature));
}

test "leanSPHINCS signs and verifies" {
    var key = try lpq.SphincsSecretKey.fromSeed([_]u8{2} ** 32, kept_height);
    defer key.deinit();
    try std.testing.expectEqual(@as(u32, kept_height), try key.keptHeight());
    const public_key = try key.publicKey();
    const signature = try key.sign(message);

    try lpq.sphincsVerify(public_key, message, &signature);
    try std.testing.expectError(error.InvalidSignature, lpq.sphincsVerify(public_key, other_message, &signature));
}

test "secret keys round trip through bytes" {
    var xmss = try lpq.XmssSecretKey.generate();
    defer xmss.deinit();
    var xmss_restored = try lpq.XmssSecretKey.fromBytes(&try xmss.toBytes());
    defer xmss_restored.deinit();
    try std.testing.expectEqual(try xmss.publicKey(), try xmss_restored.publicKey());

    var sphincs = try lpq.SphincsSecretKey.generate(kept_height);
    defer sphincs.deinit();
    const sphincs_bytes = try sphincs.toBytes();
    var sphincs_restored = try lpq.SphincsSecretKey.fromBytes(&sphincs_bytes);
    defer sphincs_restored.deinit();
    try std.testing.expectEqual(try sphincs.publicKey(), try sphincs_restored.publicKey());
    try std.testing.expectEqual(@as(u32, kept_height), try sphincs_restored.keptHeight());
    try std.testing.expectEqual(sphincs_bytes, try sphincs_restored.toBytes());
}

test "aggregates recursively and round trips through bytes" {
    const allocator = std.testing.allocator;
    try lpq.setup();

    var xmss_key = try lpq.XmssSecretKey.fromSeed([_]u8{3} ** 32);
    defer xmss_key.deinit();
    var sphincs_key = try lpq.SphincsSecretKey.fromSeed([_]u8{4} ** 32, kept_height);
    defer sphincs_key.deinit();
    var extra_key = try lpq.XmssSecretKey.fromSeed([_]u8{5} ** 32);
    defer extra_key.deinit();
    const xmss_public_key = try xmss_key.publicKey();
    const sphincs_public_key = try sphincs_key.publicKey();
    const extra_public_key = try extra_key.publicKey();

    var xmss_leaf = try lpq.Aggregate.create(&.{}, &.{.{
        .public_key = xmss_public_key,
        .message = message,
        .signature = try xmss_key.sign(message, 0),
    }}, &.{});
    defer xmss_leaf.deinit();
    var sphincs_leaf = try lpq.Aggregate.create(&.{}, &.{}, &.{.{
        .public_key = sphincs_public_key,
        .message = message,
        .signature = try sphincs_key.sign(message),
    }});
    defer sphincs_leaf.deinit();
    var root = try lpq.Aggregate.create(&.{ &xmss_leaf, &sphincs_leaf }, &.{.{
        .public_key = extra_public_key,
        .message = other_message,
        .signature = try extra_key.sign(other_message, 0),
    }}, &.{});
    defer root.deinit();

    const encoded = try root.toBytes(allocator);
    defer allocator.free(encoded);
    var restored = try lpq.Aggregate.fromBytes(encoded);
    defer restored.deinit();

    var expected_xmss = [_]lpq.Claim{
        .{ .public_key = xmss_public_key, .message = message },
        .{ .public_key = extra_public_key, .message = other_message },
    };
    std.mem.sortUnstable(lpq.Claim, &expected_xmss, {}, claimLessThan);
    const xmss_claims = try restored.xmssClaims(allocator);
    defer allocator.free(xmss_claims);
    std.mem.sortUnstable(lpq.Claim, xmss_claims, {}, claimLessThan);
    try std.testing.expectEqualSlices(lpq.Claim, &expected_xmss, xmss_claims);

    const sphincs_claims = try restored.sphincsClaims(allocator);
    defer allocator.free(sphincs_claims);
    try std.testing.expectEqualSlices(
        lpq.Claim,
        &.{.{ .public_key = sphincs_public_key, .message = message }},
        sphincs_claims,
    );

    const tampered = try allocator.dupe(u8, encoded);
    defer allocator.free(tampered);
    tampered[tampered.len / 2] ^= 1;
    try std.testing.expectError(error.NativeFailure, lpq.Aggregate.fromBytes(tampered));
}

fn claimLessThan(_: void, a: lpq.Claim, b: lpq.Claim) bool {
    return std.mem.order(u8, std.mem.asBytes(&a), std.mem.asBytes(&b)) == .lt;
}
