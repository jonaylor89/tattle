import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// Bar widget: an eye that watches your network. Left click opens the panel,
// right click toggles filtering, middle click opens the full monitor.
Panel {
  id: root
  moduleName: "tattle"
  ipcTarget: "tattle"

  readonly property string pluginId: "jonaylor89.tattle"
  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color accent: Commons.Color.accent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property bool connected: client.connected
  readonly property bool filtering: client.filtering
  readonly property int waiting: client.prompts.length
  readonly property var status: client.status

  // Flash the eye when something gets blocked.
  property real lastDenied: -1
  property bool flash: false
  property int phraseIndex: 0
  property var recentDenied: []
  property bool daemonInstalled: true
  property string actionError: ""

  // The map: places your apps talked to in the last hour.
  property var mapView: null
  readonly property var mapPlaces: mapView && mapView.places instanceof Array ? mapView.places : []
  readonly property string geoState: mapView && mapView.geo ? String(mapView.geo.state || "missing") : ""
  readonly property int mapCountries: {
    var seen = {}, n = 0
    for (var i = 0; i < mapPlaces.length; i++) {
      var cc = String(mapPlaces[i].cc || "")
      if (cc && !seen[cc]) { seen[cc] = true; n++ }
    }
    return n
  }

  // Keyboard cursor: 0 switch, 1 mode, 2 profile, 3 alerts, 4 open monitor.
  property int cursor: -1
  property int modeCursor: 0
  property int profileCursor: 0

  readonly property var modes: [
    { value: "alert", label: strings.t("mode.alert") },
    { value: "silent-allow", label: strings.t("mode.allow") },
    { value: "silent-deny", label: strings.t("mode.deny") }
  ]
  readonly property var profileOptions: {
    var out = [{ value: "", label: strings.t("profile.none") }]
    for (var i = 0; i < client.profiles.length; i++) out.push({ value: String(client.profiles[i]), label: Model.clip(client.profiles[i], 24) })
    return out
  }

  readonly property var phrases: [
    strings.t("phrase.1"), strings.t("phrase.2"), strings.t("phrase.3"), strings.t("phrase.4"),
    strings.t("phrase.5"), strings.t("phrase.6"), strings.t("phrase.7"), strings.t("phrase.8")
  ]

  readonly property string eyeGlyph: !connected || !filtering ? "󰈉" : "󰈈"
  readonly property color eyeColor: {
    if (!connected) return Qt.darker(barForeground, 1.8)
    if (waiting > 0 || flash) return urgent
    if (!filtering) return Qt.darker(barForeground, 1.55)
    return barForeground
  }

  readonly property string heroMeta: {
    if (!connected) return daemonInstalled ? strings.t("hero.notRunning") : strings.t("hero.notInstalled")
    if (!filtering) return strings.t("hero.off")
    if (waiting > 0) return strings.tn("hero.waiting", waiting).arg(waiting)
    return phrases[phraseIndex % phrases.length]
  }

  readonly property string tooltip: {
    if (!connected) return "Tattle — " + strings.t("hero.notRunning")
    var s = "Tattle · " + (filtering ? modeLabel(client.mode) : strings.t("hero.off"))
    s += "\n↑ " + Model.rate(client.txRate) + "   ↓ " + Model.rate(client.rxRate)
    if (status) s += "\n✓ " + status.allowed + "   ✗ " + status.denied
    if (waiting > 0) s += "\n" + strings.tn("hero.waiting", waiting).arg(waiting)
    return s
  }

  function modeLabel(m) {
    for (var i = 0; i < modes.length; i++) if (modes[i].value === m) return modes[i].label
    return m
  }

  function serviceInstance() {
    return bar && bar.shell && typeof bar.shell.serviceFor === "function" ? bar.shell.serviceFor(pluginId) : null
  }

  function showAlerts() {
    var svc = serviceInstance()
    if (svc && typeof svc.showAlerts === "function") svc.showAlerts()
    close()
  }

  function openMonitor() {
    Quickshell.execDetached(["omarchy-launch-tui", "tattle"])
    close()
  }

  function openMap() {
    Quickshell.execDetached(["omarchy-launch-tui", "tattle", "map"])
    close()
  }

  function refreshMap() {
    client.call("map", { since: 3600, limit: 0 }, function(ok, data) {
      // An older daemon without a map simply hides the section.
      root.mapView = ok && data && data.geo ? data : null
    })
  }

  function placeLine(p) {
    if (!p) return ""
    var where = p.city ? p.city + (p.country ? ", " + p.country : "") : (p.country || p.cc || "")
    var apps = p.apps instanceof Array && p.apps.length ? " — " + p.apps.slice(0, 3).join(", ") : ""
    var bytes = (Number(p.tx) || 0) + (Number(p.rx) || 0)
    var tail = bytes > 0 ? " · " + Model.bytes(bytes) : ((Number(p.denied) || 0) > 0 ? " · ✗ " + p.denied : "")
    return Model.clip(where, 40) + Model.clip(apps, 60) + tail
  }

  function setup() {
    actionError = ""
    if (daemonInstalled) {
      // The binary is there; the service just isn't running.
      Quickshell.execDetached(["pkexec", "systemctl", "enable", "--now", "tattle.service"])
    } else {
      var script = String(Qt.resolvedUrl("../install.sh")).replace(/^file:\/\//, "")
      Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", "bash " + Util.shellQuote(script)])
    }
    close()
  }

  function refreshDenied() {
    client.call("log", { limit: 200, denied: true }, function(ok, data) {
      if (!ok || !(data instanceof Array)) return
      // Newest first, one row per app and server, with a repeat count.
      var rows = [], seen = {}
      for (var i = data.length - 1; i >= 0; i--) {
        var e = data[i]
        if (!e || !e.conn) continue
        var key = Model.processName(e.conn.process) + "|" + Model.host(e.conn) + "|" + Model.port(e.conn)
        if (seen[key] !== undefined) { rows[seen[key]].count++; continue }
        if (rows.length >= 5) continue
        seen[key] = rows.length
        rows.push({ conn: e.conn, count: 1 })
      }
      root.recentDenied = rows
    })
  }

  function cycleMode(delta) {
    var i = 0
    for (var k = 0; k < modes.length; k++) if (modes[k].value === client.mode) i = k
    client.setMode(modes[(i + delta + modes.length) % modes.length].value)
  }

  function moveCursor(dy) {
    var order = [0, 1]
    if (profileOptions.length > 1) order.push(2)
    if (waiting > 0) order.push(3)
    order.push(4)
    var at = order.indexOf(cursor)
    if (at < 0) { cursor = order[0]; return }
    cursor = order[Math.max(0, Math.min(order.length - 1, at + dy))]
  }

  function moveSideways(dx) {
    if (cursor === 1) modeCursor = Math.max(0, Math.min(modes.length - 1, modeCursor + dx))
    else if (cursor === 2) profileCursor = Math.max(0, Math.min(profileOptions.length - 1, profileCursor + dx))
  }

  function activate() {
    if (cursor === 0) client.setFiltering(!filtering)
    else if (cursor === 1) client.setMode(modes[modeCursor].value)
    else if (cursor === 2) client.setProfile(profileOptions[profileCursor].value)
    else if (cursor === 3) showAlerts()
    else if (cursor === 4) openMonitor()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    cursor = -1
    phraseIndex = Math.floor(Math.random() * phrases.length)
    for (var i = 0; i < modes.length; i++) if (modes[i].value === client.mode) modeCursor = i
    profileCursor = 0
    for (var j = 0; j < profileOptions.length; j++) if (profileOptions[j].value === client.activeProfile) profileCursor = j
    refreshDenied()
    whichProc.running = true
    Qt.callLater(function() { if (panel.loadedContent) panel.loadedContent.forceActiveFocus() })
  }

  onStatusChanged: {
    if (!status) return
    var d = Number(status.denied) || 0
    if (lastDenied >= 0 && d > lastDenied) {
      flash = true
      flashTimer.restart()
      if (opened) refreshDenied()
    }
    lastDenied = d
  }

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  TattleClient {
    id: client
    alerts: false
    traffic: true
  }

  Timer { id: flashTimer; interval: 900; onTriggered: root.flash = false }

  Timer {
    interval: 2000
    repeat: true
    triggeredOnStart: true
    running: root.opened && root.connected
    onTriggered: root.refreshMap()
  }

  Process {
    id: whichProc
    command: ["sh", "-c", "command -v tattle >/dev/null"]
    onExited: function(code) { root.daemonInstalled = code === 0 }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.eyeGlyph
    foreground: root.eyeColor
    tooltipText: root.opened ? "" : root.tooltip
    onPressed: function(b) {
      if (b === Qt.RightButton) {
        if (root.connected) client.setFiltering(!root.filtering)
      } else if (b === Qt.MiddleButton) {
        root.openMonitor()
      } else {
        root.toggle()
      }
    }

    // Badge for waiting alerts.
    Rectangle {
      visible: root.waiting > 0
      width: Math.max(Style.space(6), 6)
      height: width
      radius: width / 2
      color: root.urgent
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.rightMargin: Style.space(4)
      anchors.topMargin: Style.space(4)
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(1100))

    content: PanelKeyCatcher {
      id: keyCatcher
      implicitHeight: column.implicitHeight
      anchors.fill: parent
      onMoveRequested: function(dx, dy) {
        if (root.cursor < 0) { root.cursor = 0; return }
        if (dy !== 0) root.moveCursor(dy)
        else root.moveSideways(dx)
      }
      onActivateRequested: if (root.cursor >= 0) root.activate()
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "f" || t === "F") client.setFiltering(!root.filtering)
        else if (t === "m" || t === "M") root.cycleMode(1)
        else if (t === "o" || t === "O") root.openMonitor()
        else if ((t === "a" || t === "A") && root.waiting > 0) root.showAlerts()
      }

      Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: parent.width
          spacing: Style.space(12)

          PanelHero {
            id: hero
            width: parent.width
            title: "Tattle"
            meta: root.heroMeta
            foreground: root.foreground
            fontFamily: root.fontFamily
            iconOpacity: root.connected && root.filtering ? 1.0 : 0.5
            iconComponent: Component {
              Text {
                textFormat: Text.PlainText
                text: root.eyeGlyph
                color: root.waiting > 0 ? root.urgent : root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.display
              }
            }
            trailingControl: Component {
              ToggleSwitch {
                id: powerSwitch
                visible: root.connected
                checked: root.filtering
                hasCursor: root.cursor === 0
                foreground: root.foreground
                onToggled: client.setFiltering(!root.filtering)
                onHovered: function(on) { if (on) root.cursor = 0 }
                PanelToolTip {
                  visible: powerSwitch.containsMouse
                  text: root.filtering ? strings.t("switch.off") : strings.t("switch.on")
                  fontFamily: root.fontFamily
                }
              }
            }
          }

          // Daemon missing or stopped.
          CursorSurface {
            visible: !root.connected
            width: parent.width
            implicitHeight: setupCol.implicitHeight + Style.space(24)
            foreground: root.foreground
            Column {
              id: setupCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.margins: Style.space(12)
              spacing: Style.space(10)
              Text {
                width: parent.width
                textFormat: Text.PlainText
                text: root.daemonInstalled ? strings.t("setup.start") : strings.t("setup.install")
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                wrapMode: Text.WordWrap
              }
              Button {
                text: root.daemonInstalled ? strings.t("setup.startButton") : strings.t("setup.installButton")
                foreground: root.foreground
                bordered: true
                fontFamily: root.fontFamily
                onClicked: root.setup()
              }
            }
          }

          Column {
            visible: root.connected
            width: parent.width
            spacing: Style.space(12)

            // Mode.
            Column {
              width: parent.width
              spacing: Style.space(6)
              PanelSectionHeader { text: strings.t("section.mode"); foreground: root.foreground; fontFamily: root.fontFamily }
              ButtonGroup {
                options: root.modes
                value: client.mode
                foreground: root.foreground
                accent: root.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                focusable: false
                cursorIndex: root.cursor === 1 ? root.modeCursor : -1
                onChanged: function(v) { client.setMode(v) }
                onHovered: function(i, on) { if (on) { root.cursor = 1; root.modeCursor = i } }
              }
            }

            // Profile.
            Column {
              visible: root.profileOptions.length > 1
              width: parent.width
              spacing: Style.space(6)
              PanelSectionHeader { text: strings.t("section.profile"); foreground: root.foreground; fontFamily: root.fontFamily }
              Flow {
                width: parent.width
                ButtonGroup {
                  options: root.profileOptions
                  value: client.activeProfile
                  foreground: root.foreground
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  focusable: false
                  cursorIndex: root.cursor === 2 ? root.profileCursor : -1
                  onChanged: function(v) { client.setProfile(v) }
                  onHovered: function(i, on) { if (on) { root.cursor = 2; root.profileCursor = i } }
                }
              }
            }

            // Waiting alerts.
            CursorSurface {
              visible: root.waiting > 0
              width: parent.width
              implicitHeight: Style.space(40)
              hasCursor: root.cursor === 3
              foreground: root.urgent
              Text {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.space(12)
                anchors.rightMargin: Style.space(12)
                textFormat: Text.PlainText
                text: "󰀦  " + strings.tn("hero.waiting", root.waiting).arg(root.waiting) + " — " + strings.t("alerts.show")
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                elide: Text.ElideRight
              }
              MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onEntered: root.cursor = 3
                onClicked: root.showAlerts()
              }
            }

            PanelSeparator { width: parent.width; foreground: root.foreground }

            // Where your apps connect.
            Column {
              visible: root.mapView !== null
              width: parent.width
              spacing: Style.space(6)
              Item {
                width: parent.width
                height: mapHeader.implicitHeight
                PanelSectionHeader { id: mapHeader; text: strings.t("section.map"); foreground: root.foreground; fontFamily: root.fontFamily }
                Text {
                  visible: root.geoState === "ready"
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  textFormat: Text.PlainText
                  text: strings.tn("map.places", root.mapPlaces.length).arg(root.mapPlaces.length)
                    + " · " + strings.tn("map.countries", root.mapCountries).arg(root.mapCountries)
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
              }
              WorldMap {
                id: worldMap
                visible: root.geoState === "ready"
                width: parent.width
                places: root.mapPlaces
                home: root.mapView ? root.mapView.home : null
                foreground: root.foreground
                accent: root.accent
                urgent: root.urgent
                running: root.opened
                onClicked: root.openMap()
              }
              Text {
                visible: root.geoState === "ready"
                width: parent.width
                textFormat: Text.PlainText
                text: root.mapPlaces.length === 0 ? strings.t("map.empty") : root.placeLine(worldMap.hovered || root.mapPlaces[0])
                color: worldMap.hovered ? root.foreground : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }
              // No location data yet.
              Item {
                visible: root.geoState === "missing" || root.geoState === "downloading"
                width: parent.width
                implicitHeight: Math.max(geoText.implicitHeight, geoButton.implicitHeight)
                Text {
                  id: geoText
                  anchors.left: parent.left
                  anchors.right: geoButton.visible ? geoButton.left : parent.right
                  anchors.rightMargin: Style.space(10)
                  anchors.verticalCenter: parent.verticalCenter
                  textFormat: Text.PlainText
                  text: root.geoState === "downloading" ? strings.t("map.downloading")
                    : (root.mapView && root.mapView.geo && root.mapView.geo.error
                      ? strings.t("map.failed").arg(Model.clip(root.mapView.geo.error, 120))
                      : strings.t("map.missing"))
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WordWrap
                }
                Button {
                  id: geoButton
                  visible: root.geoState === "missing"
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  text: strings.t("map.download")
                  foreground: root.foreground
                  bordered: true
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: client.call("geo_update", {}, function() { root.refreshMap() })
                }
              }
            }

            PanelSeparator { visible: root.mapView !== null; width: parent.width; foreground: root.foreground }

            // Live traffic.
            Column {
              width: parent.width
              spacing: Style.space(6)
              Item {
                width: parent.width
                height: trafficHeader.implicitHeight
                PanelSectionHeader { id: trafficHeader; text: strings.t("section.traffic"); foreground: root.foreground; fontFamily: root.fontFamily }
                Text {
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  textFormat: Text.PlainText
                  text: "↑ " + Model.rate(client.txRate) + "   ↓ " + Model.rate(client.rxRate)
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
              }
              Text {
                visible: client.apps.length === 0
                width: parent.width
                textFormat: Text.PlainText
                text: strings.t("traffic.quiet")
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }
              Repeater {
                model: client.apps.slice(0, 7)
                delegate: AppRow {
                  required property var modelData
                  width: column.width
                  app: modelData
                  peak: {
                    var m = 1
                    for (var i = 0; i < client.apps.length; i++) m = Math.max(m, client.apps[i].tx_rate + client.apps[i].rx_rate)
                    return m
                  }
                }
              }
            }

            // Recently blocked.
            Column {
              visible: root.recentDenied.length > 0
              width: parent.width
              spacing: Style.space(6)
              PanelSeparator { width: parent.width; foreground: root.foreground }
              PanelSectionHeader { text: strings.t("section.blocked"); foreground: root.foreground; fontFamily: root.fontFamily }
              Repeater {
                model: root.recentDenied
                delegate: Item {
                  required property var modelData
                  width: column.width
                  height: Style.space(20)
                  Text {
                    id: blockedName
                    width: Style.space(110)
                    anchors.verticalCenter: parent.verticalCenter
                    textFormat: Text.PlainText
                    text: Model.clip(Model.processName(modelData.conn.process), 40)
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideRight
                  }
                  Text {
                    anchors.left: blockedName.right
                    anchors.right: parent.right
                    anchors.leftMargin: Style.space(8)
                    anchors.verticalCenter: parent.verticalCenter
                    textFormat: Text.PlainText
                    text: "✗ " + Model.clip(Model.host(modelData.conn), 80) + ":" + Model.port(modelData.conn)
                      + (modelData.count > 1 ? "  ×" + modelData.count : "")
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideMiddle
                  }
                }
              }
            }

            PanelSeparator { width: parent.width; foreground: root.foreground }

            Item {
              width: parent.width
              height: openButton.implicitHeight
              Text {
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                textFormat: Text.PlainText
                text: root.status
                  ? strings.t("footer.stats").arg(root.status.rules).arg(root.status.allowed).arg(root.status.denied)
                  : ""
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
              Button {
                id: openButton
                anchors.right: parent.right
                text: strings.t("footer.open")
                iconText: "󰍉"
                foreground: root.foreground
                bordered: true
                hasCursor: root.cursor === 4
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                tooltipText: "O"
                onClicked: root.openMonitor()
                onHovered: function(on) { if (on) root.cursor = 4 }
              }
            }
          }
        }
      }
    }
  }

  component AppRow: Item {
    id: appRow
    property var app: null
    property real peak: 1
    height: Style.space(24)

    readonly property real total: app ? (Number(app.tx_rate) || 0) + (Number(app.rx_rate) || 0) : 0

    // Activity bar behind the row, scaled to the busiest app.
    Rectangle {
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      height: parent.height - Style.space(4)
      radius: Style.cornerRadius > 0 ? Style.space(4) : 0
      width: Math.max(0, parent.width * Math.min(1, appRow.total / Math.max(1, appRow.peak)))
      color: Util.alpha(root.accent, 0.12)
      Behavior on width { NumberAnimation { duration: Style.duration(240); easing.type: Easing.OutCubic } }
    }
    Text {
      id: nameText
      anchors.left: parent.left
      anchors.leftMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width * 0.45
      textFormat: Text.PlainText
      text: appRow.app ? Model.clip(Model.displayName(appRow.app.identity), 48) : ""
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      elide: Text.ElideRight
    }
    Text {
      anchors.right: parent.right
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      text: appRow.app ? "↑ " + Model.rate(appRow.app.tx_rate) + "  ↓ " + Model.rate(appRow.app.rx_rate) : ""
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
  }
}
