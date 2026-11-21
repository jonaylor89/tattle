.pragma library

// Pure helpers shared by the alert service and the bar panel.

function clip(text, max) {
  var s = String(text === undefined || text === null ? "" : text)
  return s.length > max ? s.slice(0, max - 1) + "…" : s
}

function bytes(n) {
  var v = Number(n) || 0
  var units = ["B", "KB", "MB", "GB", "TB"]
  var i = 0
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++ }
  if (i === 0) return Math.round(v) + " B"
  return (v < 10 ? v.toFixed(1) : Math.round(v)) + " " + units[i]
}

function rate(n) {
  var v = Number(n) || 0
  return v <= 0 ? "—" : bytes(v) + "/s"
}

// Display name for a process identity: script for interpreters
// ("python3 -m http.server"), otherwise the executable's basename.
function displayName(identity) {
  var id = String(identity || "")
  if (id === "*") return "any app"
  var parts = id.split(" :: ")
  var base = function(p) { var s = p.split("/"); return s[s.length - 1] }
  if (parts.length > 1) {
    if (parts[1].indexOf("-m ") === 0) return base(parts[0]) + " " + parts[1]
    return base(parts[1])
  }
  return base(id)
}

function processName(proc) {
  if (!proc) return ""
  var id = String(proc.exe || "")
  if (proc.script) id += " :: " + String(proc.script)
  return displayName(id)
}

function host(conn) {
  if (!conn) return ""
  if (conn.hostnames instanceof Array && conn.hostnames.length > 0) return String(conn.hostnames[0])
  return String(conn.remote_ip || "")
}

function port(conn) {
  if (!conn) return 0
  return conn.direction === "in" ? Number(conn.local_port) : Number(conn.remote_port)
}

// The server choices an alert offers, most specific first.
function remoteOptions(prompt, anyLabel) {
  var out = []
  if (!prompt || !prompt.conn) return out
  var c = prompt.conn
  if (c.hostnames instanceof Array && c.hostnames.length > 0) out.push({ value: "host", label: clip(c.hostnames[0], 40) })
  if (prompt.domain) out.push({ value: "domain", label: clip("*." + prompt.domain, 40) })
  out.push({ value: "ip", label: clip(c.remote_ip, 40) })
  out.push({ value: "any", label: anyLabel })
  return out
}

function defaultRemote(options) {
  for (var i = 0; i < options.length; i++) if (options[i].value === "domain") return "domain"
  return options.length > 0 ? options[0].value : "any"
}

var LIFETIMES = ["once", "until_quit", "forever", "hour"]

function lifetimeValue(key) {
  if (key === "hour") return { "for": 3600 }
  return key
}

function decision(action, remote, portOnly, anyApp, lifetime) {
  return {
    action: action,
    remote: remote,
    port_only: !!portOnly,
    any_process: !!anyApp,
    lifetime: lifetimeValue(lifetime),
    in_profile: false
  }
}

// Icon for an executable: its desktop entry's icon, or a themed icon of the
// same name. `lookup` and `iconPath` are DesktopEntries.heuristicLookup and
// Quickshell.iconPath, passed in because this is a library script.
function iconFor(exe, lookup, iconPath) {
  var name = String(exe || "").split("/").pop()
  if (!name || name.charAt(0) === "[") return ""
  var entry = lookup(name)
  if (entry && entry.icon) {
    var icon = String(entry.icon)
    if (icon.charAt(0) === "/") return "file://" + icon
    var p = iconPath(icon, true)
    if (p) return p
  }
  return iconPath(name, true) || ""
}

// "󰍎 Frankfurt, Germany · Amazon.com, Inc." from a prompt's geo field.
function placeLine(geo) {
  if (!geo) return ""
  var where = geo.city ? geo.city + (geo.country ? ", " + geo.country : "") : (geo.country || geo.cc || "")
  if (!where) return ""
  return "󰍎 " + clip(where, 60) + (geo.org ? "  ·  " + clip(geo.org, 60) : "")
}
