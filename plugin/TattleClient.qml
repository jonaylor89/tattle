import QtQuick
import Quickshell
import Quickshell.Io

// One connection to the tattle daemon's control socket
// (newline-delimited JSON, see src/proto.rs). Reconnects on its own.
//
// Everything that arrives here is untrusted: host names come straight
// from DNS answers. Every Text that shows it must be Text.PlainText.
Item {
  id: root
  visible: false

  property string socketPath: Quickshell.env("TATTLE_SOCKET") || "/run/tattle/tattle.sock"
  // This client answers connection alerts.
  property bool alerts: false
  // Receive per-app traffic rates every two seconds.
  property bool traffic: true

  readonly property bool connected: sock.connected
  property bool everConnected: false
  property var status: null
  property var prompts: []
  property var apps: []
  property real txRate: 0
  property real rxRate: 0

  readonly property bool filtering: !!status && !!status.settings && status.settings.enabled === true
  readonly property string mode: status && status.settings ? String(status.settings.mode || "alert") : "alert"
  readonly property var profiles: status && status.settings && status.settings.profiles instanceof Array ? status.settings.profiles : []
  readonly property string activeProfile: status && status.settings && status.settings.active_profile ? String(status.settings.active_profile) : ""

  signal promptAdded(var prompt)
  signal promptRemoved(int id)
  signal rulesChanged()

  property int _nextId: 1
  property var _callbacks: ({})

  function call(cmd, args, callback) {
    if (!sock.connected) {
      if (callback) callback(false, null, "not connected")
      return
    }
    var id = _nextId++
    var msg = { id: id, cmd: cmd }
    if (args) for (var k in args) msg[k] = args[k]
    if (callback) _callbacks[id] = callback
    sock.write(JSON.stringify(msg) + "\n")
    sock.flush()
  }

  function setMode(m) { call("set_mode", { mode: m }) }
  function setFiltering(on) { call("set_enabled", { enabled: !!on }) }
  function setProfile(p) { call("set_profile", { profile: p === "" ? null : p }) }

  function _handle(line) {
    if (line.length > 4 * 1024 * 1024) return
    var m
    try { m = JSON.parse(line) } catch (e) { return }
    if (!m || typeof m !== "object") return
    if (m.event !== undefined) {
      _event(String(m.event), m.data)
      return
    }
    var cb = m.id !== undefined && m.id !== null ? _callbacks[m.id] : undefined
    if (cb) {
      delete _callbacks[m.id]
      cb(m.ok === true, m.data, m.error ? String(m.error) : "")
    }
  }

  function _event(kind, data) {
    if (kind === "status") {
      status = data
    } else if (kind === "prompt") {
      if (!data || typeof data.id !== "number") return
      for (var i = 0; i < prompts.length; i++) if (prompts[i].id === data.id) return
      prompts = prompts.concat([data])
      promptAdded(data)
    } else if (kind === "prompt_resolved") {
      var id = data ? data.id : -1
      var next = prompts.filter(function(p) { return p.id !== id })
      if (next.length !== prompts.length) {
        prompts = next
        promptRemoved(id)
      }
    } else if (kind === "traffic") {
      apps = data && data.apps instanceof Array ? data.apps.slice(0, 50) : []
      txRate = data ? Number(data.tx_rate) || 0 : 0
      rxRate = data ? Number(data.rx_rate) || 0 : 0
    } else if (kind === "rules_changed") {
      rulesChanged()
    }
  }

  Socket {
    id: sock
    path: root.socketPath
    parser: SplitParser {
      onRead: function(data) { root._handle(String(data)) }
    }
    onConnectionStateChanged: {
      if (connected) {
        root.everConnected = true
        root.call("subscribe", { alerts: root.alerts, traffic: root.traffic })
      } else {
        root.status = null
        root.prompts = []
        root.apps = []
        root.txRate = 0
        root.rxRate = 0
        root._callbacks = ({})
        retry.restart()
      }
    }
    onError: function(error) { retry.restart() }
  }

  Timer {
    id: retry
    interval: 3000
    onTriggered: if (!sock.connected) sock.connected = true
  }

  Component.onCompleted: sock.connected = true
}
