/* address.js — 주소 표현식 해석, covers, matches (SPEC 2 서두, 2-3, 2-7 알 수 없는 주소)
 *
 * 표현식: 'Any' | 구역 이름 | 주소 그룹 이름 | 단일 IPv4
 * 해석 결과: { ok:true, any:true } 또는 { ok:true, any:false, zones:[구역이름], ips:[정수] }
 *           { ok:false, error:'알 수 없는 주소' } */
(function (root) {
  'use strict';

  var topo = (root.PW && root.PW.topology) || require('./topology.js');
  var ERR = '알 수 없는 주소';

  function intToIp(n) {
    return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256,
      Math.floor(n / 256) % 256, n % 256].join('.');
  }

  function unique(list) {
    return list.filter(function (v, i) { return list.indexOf(v) === i; });
  }

  function resolve(expr) {
    if (typeof expr !== 'string') return { ok: false, error: ERR };
    var s = expr.trim();
    if (/^any$/i.test(s)) return { ok: true, any: true };

    if (topo.isZoneName(s)) return { ok: true, any: false, zones: [s], ips: [] };

    var g = topo.findGroup(s);
    if (g) {
      var zones = [], ips = [];
      for (var i = 0; i < g.members.length; i++) {
        var m = g.members[i];
        if (m.zone) {
          zones.push(m.zone);
        } else if (m.host) {
          var h = topo.findHost(m.host);
          if (!h) return { ok: false, error: ERR };
          ips.push(topo.ipToInt(h.ip));
        }
      }
      return { ok: true, any: false, zones: unique(zones), ips: unique(ips) };
    }

    var n = topo.ipToInt(s);
    if (n !== null) return { ok: true, any: false, zones: [], ips: [n] };

    return { ok: false, error: ERR };
  }

  // 해석된 주소 a 가 b 를 완전히 덮는가 (SPEC 2-3)
  //  - a 가 Any 이면 참, b 가 Any 인데 a 가 아니면 거짓
  //  - b 의 구역은 모두 a 의 구역이어야 하고 (구역 전체는 구역으로만 덮을 수 있다)
  //  - b 의 IP 는 a 의 IP 이거나 a 의 구역에 속해야 한다
  function covers(a, b) {
    if (a.any) return true;
    if (b.any) return false;
    var zonesOk = b.zones.every(function (z) { return a.zones.indexOf(z) !== -1; });
    if (!zonesOk) return false;
    return b.ips.every(function (ip) {
      return a.ips.indexOf(ip) !== -1 || a.zones.indexOf(topo.zoneOf(intToIp(ip))) !== -1;
    });
  }

  // 해석된 주소 a 에 패킷의 IP(문자열)가 속하는가
  function matches(a, ip) {
    if (a.any) return true;
    var n = topo.ipToInt(ip);
    if (n === null) return false;
    return a.ips.indexOf(n) !== -1 || a.zones.indexOf(topo.zoneOf(ip)) !== -1;
  }

  var api = { ERR: ERR, resolve: resolve, covers: covers, matches: matches, intToIp: intToIp };

  root.PW = root.PW || {};
  root.PW.address = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
