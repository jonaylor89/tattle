import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// Always-on service: answers tattle's connection alerts with a themed
// overlay card, the way Little Snitch pops its alert window.
Item {
  id: root

  property var manifest: null
  property var shell: null

  readonly property alias client: client
  // "Decide later": the card hides but the alert keeps waiting (and its
  // countdown keeps running) until answered from the bar or it times out.
  property bool deferred: false
  readonly property var current: client.prompts.length > 0 ? client.prompts[0] : null
  readonly property bool showing: current !== null && !deferred

  property var remoteOptions: []
  property string remoteChoice: "domain"
  property string portChoice: "only"
  property string appChoice: "only"
  property string lifetimeChoice: "forever"
  property int row: 0
  property double shownAt: 0
  property double nowMs: Date.now()
  property string error: ""
  property bool busy: false

  // Keystrokes that land in the first moments were meant for something else.
  readonly property int inputGuardMs: 700
  readonly property bool testMode: Quickshell.env("TATTLE_ALERT_TEST") === "1"

  readonly property color fg: Commons.Color.popups.text
  readonly property color bg: Commons.Color.popups.background
  readonly property color accent: Commons.Color.accent
  readonly property color urgent: Commons.Color.urgent
  readonly property color dim: Qt.darker(fg, 1.55)
  readonly property string fontFamily: Style.font.family

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  function t(key) { return strings.t(key) }

  function showAlerts() {
    if (client.prompts.length === 0) return
    deferred = false
    shownAt = Date.now()
  }

  function resetChoices() {
    remoteOptions = Model.remoteOptions(current, t("alert.anyServer"))
    remoteChoice = Model.defaultRemote(remoteOptions)
    portChoice = "only"
    appChoice = "only"
    lifetimeChoice = "forever"
    row = 0
    error = ""
    busy = false
    shownAt = Date.now()
  }

  function decide(action) {
    if (!current || busy) return
    if (Date.now() - shownAt < inputGuardMs) return
    busy = true
    var id = current.id
    client.call("decide", {
      prompt_id: id,
      decision: Model.decision(action, remoteChoice, portChoice === "only", appChoice === "any", lifetimeChoice)
    }, function(ok, data, err) {
      root.busy = false
      if (!ok) root.error = Model.clip(err, 200)
    })
  }

  function cycle(options, value, delta) {
    var i = 0
    for (var k = 0; k < options.length; k++) if (options[k].value === value) i = k
    i = (i + delta + options.length) % options.length
    return options[i].value
  }

  function adjustRow(delta) {
    if (row === 0) remoteChoice = cycle(remoteOptions, remoteChoice, delta)
    else if (row === 1) portChoice = cycle(portOptions, portChoice, delta)
    else if (row === 2) appChoice = cycle(appOptions, appChoice, delta)
    else if (row === 3) lifetimeChoice = cycle(lifetimeOptions, lifetimeChoice, delta)
  }

  readonly property var conn: current ? current.conn : null
  readonly property string appName: conn ? Model.clip(Model.processName(conn.process), 40) : ""
  readonly property int connPort: Model.port(conn)
  readonly property var portOptions: [
    { value: "only", label: t("alert.onlyPort").arg(connPort) },
    { value: "any", label: t("alert.anyPort") }
  ]
  readonly property var appOptions: [
    { value: "only", label: t("alert.onlyApp").arg(appName) },
    { value: "any", label: t("alert.anyApp") }
  ]
  readonly property var lifetimeOptions: [
    { value: "once", label: t("alert.once") },
    { value: "until_quit", label: t("alert.untilQuit") },
    { value: "forever", label: t("alert.forever") },
    { value: "hour", label: t("alert.hour") }
  ]
  readonly property real secondsLeft: current ? Math.max(0, current.deadline - nowMs / 1000) : 0
  readonly property real totalSeconds: current ? Math.max(1, current.deadline - current.created) : 1
  readonly property string iconSource: conn ? Model.iconFor(conn.process.exe, DesktopEntries.heuristicLookup, Quickshell.iconPath) : ""

  onCurrentChanged: if (current) resetChoices()

  TattleClient {
    id: client
    alerts: true
    traffic: false
    // A fresh burst of alerts brings the card back even after "later".
    onPromptAdded: function(p) { if (client.prompts.length === 1) root.deferred = false }
  }

  Timer {
    interval: 250
    repeat: true
    running: root.current !== null
    onTriggered: root.nowMs = Date.now()
  }

  ShellIpc {
    target: "tattle-alerts"
    function show(): void { root.showAlerts() }
    function hide(): void { root.deferred = true }
    function count(): string { return String(client.prompts.length) }
    // Bindable: answer the alert on screen with its current choices.
    function allow(): string { root.shownAt = 0; root.decide("allow"); return "ok" }
    function deny(): string { root.shownAt = 0; root.decide("deny"); return "ok" }
  }

  OverlayWindow {
    id: window
    shown: root.showing
    shownKeyboardFocus: root.testMode ? WlrKeyboardFocus.None : WlrKeyboardFocus.Exclusive
    WlrLayershell.namespace: "tattle-alert"

    Rectangle {
      anchors.fill: parent
      color: Util.alpha(Commons.Color.background, 0.28)
      MouseArea { anchors.fill: parent; onClicked: keys.forceActiveFocus() }
    }

    BorderSurface {
      id: card
      width: Math.min(Style.space(620), window.width - Style.gapsOut * 4)
      height: content.implicitHeight + contentTopInset + contentBottomInset
      x: (window.width - width) / 2
      y: Math.round(window.height * 0.22)
      radius: Style.cornerRadius
      color: root.bg
      borderSpec: Border.surfaceSpec("popups", "border", root.accent, Math.max(1, Style.space(2)))
      padding: Style.spacing.panelPadding

      opacity: root.showing ? 1 : 0
      scale: root.showing ? 1 : 0.97
      Behavior on opacity { NumberAnimation { duration: Style.duration(180); easing.type: Easing.OutCubic } }
      Behavior on scale { NumberAnimation { duration: Style.duration(180); easing.type: Easing.Bezier; easing.bezierCurve: Style.easeOut } }

      MouseArea { anchors.fill: parent; onClicked: keys.forceActiveFocus() }

      Item {
        id: keys
        anchors.fill: parent
        focus: true
        Keys.priority: Keys.BeforeItem
        Keys.onPressed: function(event) {
          var k = event.key
          if (k === Qt.Key_Escape) { root.deferred = true }
          else if (k === Qt.Key_A) { root.decide("allow") }
          else if (k === Qt.Key_D) { root.decide("deny") }
          else if (k === Qt.Key_Up || k === Qt.Key_K) { root.row = (root.row + 3) % 4 }
          else if (k === Qt.Key_Down || k === Qt.Key_J || k === Qt.Key_Tab) { root.row = (root.row + 1) % 4 }
          else if (k === Qt.Key_Left || k === Qt.Key_H) { root.adjustRow(-1) }
          else if (k === Qt.Key_Right || k === Qt.Key_L) { root.adjustRow(1) }
          else return
          event.accepted = true
        }
        Connections {
          target: root
          function onShowingChanged() { if (root.showing) Qt.callLater(function() { keys.forceActiveFocus() }) }
        }
      }

      Column {
        id: content
        x: card.contentLeftInset
        y: card.contentTopInset
        width: card.width - card.contentLeftInset - card.contentRightInset
        spacing: Style.space(14)

        // Who wants what.
        Row {
          width: parent.width
          spacing: Style.space(14)

          Item {
            width: Style.space(48)
            height: Style.space(48)
            Image {
              id: appIcon
              anchors.fill: parent
              source: root.iconSource
              sourceSize.width: width * 2
              sourceSize.height: height * 2
              asynchronous: true
              smooth: true
              visible: status === Image.Ready
            }
            Rectangle {
              anchors.fill: parent
              visible: appIcon.status !== Image.Ready
              radius: Style.cornerRadius > 0 ? width / 4 : 0
              color: Util.alpha(root.accent, 0.16)
              border.color: Util.alpha(root.accent, 0.5)
              border.width: 1
              Text {
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: root.appName.length > 0 ? root.appName.charAt(0).toUpperCase() : "?"
                color: root.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.display
                font.bold: true
              }
            }
          }

          Column {
            width: parent.width - Style.space(62)
            spacing: Style.space(3)

            Text {
              width: parent.width
              textFormat: Text.PlainText
              text: root.conn && root.conn.direction === "in"
                ? root.t("alert.incoming").arg(root.appName)
                : root.t("alert.outgoing").arg(root.appName)
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.subtitle
              elide: Text.ElideRight
            }
            Text {
              width: parent.width
              textFormat: Text.PlainText
              text: root.conn ? Model.clip(Model.host(root.conn), 80) : ""
              color: root.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.heading
              font.bold: true
              elide: Text.ElideMiddle
            }
            Text {
              width: parent.width
              textFormat: Text.PlainText
              text: {
                if (!root.conn) return ""
                var proto = String(root.conn.proto || "").toUpperCase()
                var svc = root.current.service ? " (" + root.current.service + ")" : ""
                var ip = root.conn.hostnames && root.conn.hostnames.length > 0 ? " · " + root.conn.remote_ip : ""
                return root.t("alert.portLine").arg(proto).arg(root.connPort) + svc + ip
              }
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              elide: Text.ElideRight
            }
            Text {
              width: parent.width
              textFormat: Text.PlainText
              text: root.conn
                ? Model.clip(root.conn.process.exe, 120) + "  ·  pid " + root.conn.process.pid + "  ·  " + Model.clip(root.conn.process.user, 32)
                : ""
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              elide: Text.ElideMiddle
            }
            Text {
              width: parent.width
              visible: !!(root.conn && root.conn.process.exe_deleted)
              textFormat: Text.PlainText
              text: root.t("alert.exeChanged")
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
          }
        }

        PanelSeparator { width: parent.width; foreground: root.fg }

        // The four choices.
        Column {
          width: parent.width
          spacing: Style.space(8)

          ChoiceRow {
            label: root.t("alert.server")
            rowIndex: 0
            options: root.remoteOptions
            value: root.remoteChoice
            onPicked: function(v) { root.remoteChoice = v }
          }
          ChoiceRow {
            label: root.t("alert.port")
            rowIndex: 1
            options: root.portOptions
            value: root.portChoice
            onPicked: function(v) { root.portChoice = v }
          }
          ChoiceRow {
            label: root.t("alert.app")
            rowIndex: 2
            options: root.appOptions
            value: root.appChoice
            onPicked: function(v) { root.appChoice = v }
          }
          ChoiceRow {
            label: root.t("alert.duration")
            rowIndex: 3
            options: root.lifetimeOptions
            value: root.lifetimeChoice
            onPicked: function(v) { root.lifetimeChoice = v }
          }
        }

        Text {
          width: parent.width
          visible: root.error !== ""
          textFormat: Text.PlainText
          text: root.error
          color: root.urgent
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // Countdown.
        Rectangle {
          width: parent.width
          height: Math.max(2, Style.space(3))
          radius: height / 2
          color: Util.alpha(root.fg, 0.10)
          Rectangle {
            height: parent.height
            radius: parent.radius
            width: parent.width * Math.min(1, root.secondsLeft / root.totalSeconds)
            color: root.secondsLeft < 10 ? root.urgent : root.accent
            Behavior on width { NumberAnimation { duration: 250; easing.type: Easing.Linear } }
          }
        }

        Item {
          width: parent.width
          height: buttons.height

          Text {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            textFormat: Text.PlainText
            text: {
              var s = root.t("alert.secondsLeft").arg(Math.ceil(root.secondsLeft))
              if (client.prompts.length > 1) s += "  ·  " + root.t("alert.ofCount").arg(client.prompts.length)
              if (root.current && root.current.attempts > 1) s += "  ·  ×" + root.current.attempts
              return s
            }
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Row {
            id: buttons
            anchors.right: parent.right
            spacing: Style.space(8)

            Button {
              text: root.t("alert.later")
              foreground: root.fg
              fontFamily: root.fontFamily
              tooltipText: "Esc"
              onClicked: root.deferred = true
            }
            Button {
              text: root.t("alert.deny")
              iconText: "󰅖"
              foreground: root.fg
              bordered: true
              fontFamily: root.fontFamily
              tooltipText: "D"
              onClicked: root.decide("deny")
            }
            Button {
              text: root.t("alert.allow")
              iconText: "󰄬"
              foreground: root.accent
              bordered: true
              selected: true
              fontFamily: root.fontFamily
              tooltipText: "A"
              onClicked: root.decide("allow")
            }
          }
        }
      }
    }
  }

  component ChoiceRow: Item {
    id: choice
    required property string label
    required property int rowIndex
    property var options: []
    property string value: ""
    signal picked(string v)

    width: parent ? parent.width : 0
    height: Math.max(labelText.implicitHeight, flow.implicitHeight)

    Text {
      id: labelText
      width: Style.space(76)
      y: Style.spacing.controlPaddingY
      textFormat: Text.PlainText
      text: choice.label
      color: root.row === choice.rowIndex ? root.accent : root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      font.bold: root.row === choice.rowIndex
      elide: Text.ElideRight
    }

    // Wraps, so long host names and IPv6 addresses never spill out.
    Flow {
      id: flow
      x: labelText.width + Style.space(8)
      width: choice.width - x
      spacing: Style.space(6)
      Repeater {
        model: choice.options
        Button {
          required property var modelData
          text: String(modelData.label)
          selected: modelData.value === choice.value
          bordered: true
          foreground: root.fg
          accent: root.accent
          fontFamily: root.fontFamily
          fontSize: Style.font.bodySmall
          onClicked: choice.picked(modelData.value)
        }
      }
    }
  }
}
