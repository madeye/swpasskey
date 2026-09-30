// Renders the swpasskey app icon (rounded indigo tile with an SF Symbol key)
// at every size macOS wants and packs it with iconutil.
//
//   swift packaging/macos/make_icon.swift packaging/macos/swpasskeyd.app/Contents/Resources/AppIcon.icns
import AppKit
import Foundation

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.icns"
let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("swpasskey-\(getpid()).iconset")
try? FileManager.default.removeItem(at: tmp)
try! FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)

func render(_ px: Int) -> Data {
  let size = NSSize(width: px, height: px)
  let image = NSImage(size: size)
  image.lockFocus()
  let rect = NSRect(origin: .zero, size: size)
  // macOS icons leave ~10% margin around the tile.
  let inset = CGFloat(px) * 0.095
  let tile = rect.insetBy(dx: inset, dy: inset)
  let path = NSBezierPath(roundedRect: tile, xRadius: tile.width * 0.225, yRadius: tile.height * 0.225)
  let gradient = NSGradient(colors: [
    NSColor(calibratedRed: 0.36, green: 0.30, blue: 0.93, alpha: 1),
    NSColor(calibratedRed: 0.18, green: 0.14, blue: 0.62, alpha: 1),
  ])!
  gradient.draw(in: path, angle: -90)
  let cfg = NSImage.SymbolConfiguration(pointSize: CGFloat(px) * 0.52, weight: .semibold)
  if let symbol = NSImage(systemSymbolName: "key.fill", accessibilityDescription: nil)?
    .withSymbolConfiguration(cfg) {
    let tinted = NSImage(size: symbol.size, flipped: false) { r in
      symbol.draw(in: r)
      NSColor.white.set()
      r.fill(using: .sourceAtop)
      return true
    }
    let s = tinted.size
    let origin = NSPoint(x: rect.midX - s.width / 2, y: rect.midY - s.height / 2)
    tinted.draw(at: origin, from: .zero, operation: .sourceOver, fraction: 1)
  }
  image.unlockFocus()
  let rep = NSBitmapImageRep(data: image.tiffRepresentation!)!
  return rep.representation(using: .png, properties: [:])!
}

for base in [16, 32, 128, 256, 512] {
  try! render(base).write(to: tmp.appendingPathComponent("icon_\(base)x\(base).png"))
  try! render(base * 2).write(to: tmp.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", tmp.path, "-o", out]
try! p.run()
p.waitUntilExit()
try? FileManager.default.removeItem(at: tmp)
exit(p.terminationStatus)
