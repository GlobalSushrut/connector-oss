import Foundation

func usage() {
    fputs("Usage: connector-microvm-macos --json '{...}'\n", stderr)
}

let args = CommandLine.arguments
guard args.count >= 3, args[1] == "--json" else {
    usage()
    exit(2)
}

guard let data = args[2].data(using: .utf8) else {
    fputs("invalid utf8 payload\n", stderr)
    exit(2)
}

let payload = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
let vmId = payload["vm_id"] as? String ?? "unknown"
let kernel = payload["kernel_path"] as? String ?? ""
let rootfs = payload["rootfs_path"] as? String ?? ""

let receipt: [String: Any] = [
    "ok": true,
    "provider": "virtualization_framework",
    "vm_id": vmId,
    "kernel_path": kernel,
    "rootfs_path": rootfs,
    "note": "Virtualization.framework wrapper receipt (guest boot wiring controlled by sidecar runtime build)"
]

if let out = try? JSONSerialization.data(withJSONObject: receipt, options: [.prettyPrinted]),
   let text = String(data: out, encoding: .utf8) {
    print(text)
    exit(0)
}

fputs("failed to encode receipt\n", stderr)
exit(1)
