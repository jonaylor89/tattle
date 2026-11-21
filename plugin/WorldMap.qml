import QtQuick
import qs.Commons
import "Land.js" as Land

// A dot-matrix world with an arc from you to every place your apps talk
// to. Live places pulse and send little packets home.
Item {
  id: map

  property var places: []
  property var home: null
  property color foreground: Color.foreground
  property color accent: Color.accent
  property color urgent: Color.urgent
  // Animate only while someone is looking.
  property bool running: false
  property var hovered: null

  readonly property real south: -56
  readonly property real north: 78
  readonly property bool anyLive: {
    for (var i = 0; i < places.length; i++) if (isLive(places[i])) return true
    return false
  }

  signal clicked()

  implicitHeight: Math.round(width * (north - south) / 360)

  property var bits: null
  Component.onCompleted: {
    // Base64 by hand: Qt.atob(string) is deprecated.
    var abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    var lut = {}
    for (var k = 0; k < abc.length; k++) lut[abc[k]] = k
    var src = Land.data.replace(/=+$/, "")
    var a = new Uint8Array(Math.floor(src.length * 3 / 4))
    var buf = 0, nbits = 0, o = 0
    for (var i = 0; i < src.length; i++) {
      buf = ((buf << 6) | lut[src[i]]) & 0xffffff
      nbits += 6
      if (nbits >= 8) { nbits -= 8; a[o++] = (buf >> nbits) & 0xff }
    }
    bits = a
    land.requestPaint()
  }

  function isLand(lon, lat) {
    if (!bits) return false
    var col = Math.floor((lon + 180) / Land.step)
    var row = Math.floor((90 - lat) / Land.step)
    if (col < 0 || col >= Land.cols || row < 0 || row >= Land.rows) return false
    var i = row * Land.cols + col
    return (bits[i >> 3] & (0x80 >> (i & 7))) !== 0
  }

  function isLive(p) { return (Number(p.active) || 0) > 0 || (Number(p.tx_rate) || 0) + (Number(p.rx_rate) || 0) > 0 }
  function isBlocked(p) { return (Number(p.allowed) || 0) === 0 && (Number(p.denied) || 0) > 0 }
  function px(lon) { return (lon + 180) / 360 * width }
  function py(lat) { return (north - lat) / (north - south) * height }

  // Quadratic arc from a to b in pixels, the short way round, bowed upwards.
  function arcFor(p) {
    var ax = px(home.lon), ay = py(home.lat)
    var bx = px(p.lon), by = py(p.lat)
    if (bx - ax > width / 2) bx -= width
    else if (ax - bx > width / 2) bx += width
    var dx = bx - ax, dy = by - ay
    var d = Math.sqrt(dx * dx + dy * dy)
    var nx = d > 0 ? dy / d : 0, ny = d > 0 ? -dx / d : 0
    if (ny > 0) { nx = -nx; ny = -ny }
    var bow = Math.min(d * 0.22, height * 0.22)
    return { ax: ax, ay: ay, bx: bx, by: by, cx: (ax + bx) / 2 + nx * bow, cy: (ay + by) / 2 + ny * bow }
  }

  function pointOn(a, t) {
    var u = 1 - t
    return { x: u * u * a.ax + 2 * u * t * a.cx + t * t * a.bx, y: u * u * a.ay + 2 * u * t * a.cy + t * t * a.by }
  }

  function colorOf(p) {
    if (isBlocked(p)) return urgent
    if (isLive(p)) return accent
    return Util.alpha(foreground, 0.55)
  }

  function placeAt(x, y) {
    var best = null, bestD = 12 * 12
    for (var i = 0; i < places.length; i++) {
      var p = places[i]
      var dx = px(p.lon) - x, dy = py(p.lat) - y
      var dd = dx * dx + dy * dy
      if (dd < bestD) { bestD = dd; best = p }
    }
    return best
  }

  onPlacesChanged: {
    // Places are fresh objects after every refresh; keep the hover on the same spot.
    if (hovered) {
      var keep = null
      for (var i = 0; i < places.length; i++)
        if (places[i].lat === hovered.lat && places[i].lon === hovered.lon) keep = places[i]
      hovered = keep
    }
    overlay.requestPaint()
  }
  onHomeChanged: overlay.requestPaint()
  onHoveredChanged: overlay.requestPaint()
  onWidthChanged: { land.requestPaint(); overlay.requestPaint() }

  Canvas {
    id: land
    anchors.fill: parent
    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      if (!map.bits || width <= 0) return
      var step = Math.max(3, width / 104)
      var r = Math.max(0.7, step * 0.26)
      ctx.fillStyle = Util.alpha(map.foreground, 0.24)
      ctx.beginPath()
      for (var y = step / 2; y < height; y += step) {
        var lat = map.north - y / height * (map.north - map.south)
        for (var x = step / 2; x < width; x += step) {
          if (!map.isLand(x / width * 360 - 180, lat)) continue
          ctx.moveTo(x + r, y)
          ctx.arc(x, y, r, 0, Math.PI * 2)
        }
      }
      ctx.fill()
    }
  }

  Canvas {
    id: overlay
    anchors.fill: parent
    property real t: 0
    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      var ps = (map.places || []).slice(0, 120)
      // Quiet first, blocked and hovered last, so they end up on top.
      ps.sort(function(a, b) {
        var ka = (a === map.hovered ? 4 : 0) + (map.isBlocked(a) ? 2 : 0) + (map.isLive(a) ? 1 : 0)
        var kb = (b === map.hovered ? 4 : 0) + (map.isBlocked(b) ? 2 : 0) + (map.isLive(b) ? 1 : 0)
        return ka - kb
      })
      var i, p, a, s
      if (map.home) {
        for (i = 0; i < ps.length; i++) {
          p = ps[i]
          a = map.arcFor(p)
          var hot = p === map.hovered
          ctx.strokeStyle = Util.alpha(hot ? map.foreground : map.colorOf(p), hot ? 0.95 : (map.isLive(p) || map.isBlocked(p) ? 0.55 : 0.25))
          ctx.lineWidth = hot ? 1.6 : 1
          for (s = -1; s <= 1; s++) {
            var off = s * width
            if (s !== 0 && Math.max(a.ax, a.bx) + off < 0) continue
            if (s !== 0 && Math.min(a.ax, a.bx) + off > width) continue
            ctx.beginPath()
            ctx.moveTo(a.ax + off, a.ay)
            ctx.quadraticCurveTo(a.cx + off, a.cy, a.bx + off, a.by)
            ctx.stroke()
          }
        }
      }
      for (i = 0; i < ps.length; i++) {
        p = ps[i]
        var x = map.px(p.lon), y = map.py(p.lat)
        var bytes = (Number(p.tx) || 0) + (Number(p.rx) || 0)
        var r = 1.6 + Math.min(2.4, Math.log(bytes + 1) / Math.LN10 / 3)
        var c = map.colorOf(p)
        if (map.isLive(p)) {
          // A ring that swells and fades.
          var phase = (overlay.t / 1.6 + (i * 0.37)) % 1
          ctx.strokeStyle = Util.alpha(c, 0.6 * (1 - phase))
          ctx.lineWidth = 1
          ctx.beginPath()
          ctx.arc(x, y, r + phase * 7, 0, Math.PI * 2)
          ctx.stroke()
        }
        ctx.fillStyle = p === map.hovered ? map.foreground : c
        ctx.beginPath()
        ctx.arc(x, y, p === map.hovered ? r + 1 : r, 0, Math.PI * 2)
        ctx.fill()
        // Packets in flight, heading the way most bytes go.
        if (map.home && map.isLive(p) && !map.isBlocked(p)) {
          a = map.arcFor(p)
          var inbound = (Number(p.rx_rate) || 0) >= (Number(p.tx_rate) || 0)
          var tt = (overlay.t / 2.2 + i * 0.29) % 1
          var q = map.pointOn(a, inbound ? 1 - tt : tt)
          var qx = q.x < 0 ? q.x + width : (q.x > width ? q.x - width : q.x)
          ctx.fillStyle = map.foreground
          ctx.beginPath()
          ctx.arc(qx, q.y, 1.4, 0, Math.PI * 2)
          ctx.fill()
        }
      }
      if (map.home) {
        var hx = map.px(map.home.lon), hy = map.py(map.home.lat)
        ctx.fillStyle = map.foreground
        ctx.beginPath()
        ctx.arc(hx, hy, 2.6, 0, Math.PI * 2)
        ctx.fill()
        ctx.strokeStyle = Util.alpha(map.foreground, 0.5)
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.arc(hx, hy, 5, 0, Math.PI * 2)
        ctx.stroke()
      }
    }
  }

  Timer {
    interval: 50
    repeat: true
    running: map.running && map.visible && map.anyLive
    onTriggered: {
      overlay.t = Date.now() / 1000
      overlay.requestPaint()
    }
  }

  MouseArea {
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onPositionChanged: function(m) { map.hovered = map.placeAt(m.x, m.y) }
    onExited: map.hovered = null
    onClicked: map.clicked()
  }
}
