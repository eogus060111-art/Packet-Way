/* service.js — 서비스 문자열 파싱·포함·일치 (SPEC 2-3 covers, 2-7 서비스 형식 오류)
 *
 * 형식: "Any" 또는 "TCP 80,443" / "UDP 514,TCP 9200" / "TCP 1000-2000" (대소문자 무관)
 * 쉼표는 포트 구분과 프로토콜 구분을 겸한다: 'TCP 또는 UDP 로 시작하는 토큰'이 새 프로토콜,
 * 숫자만 있는 토큰은 직전 프로토콜의 포트다.
 * 내부 표현: { ok:true, any:bool, ranges:[{proto, from, to}] } (ranges 는 병합·정렬됨) */
(function (root) {
  'use strict';

  var ERR = '서비스 형식 오류';

  function fail() { return { ok: false, error: ERR }; }

  function parsePort(text) {
    var m = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/.exec(text);
    if (!m) return null;
    var from = Number(m[1]);
    var to = m[2] === undefined ? from : Number(m[2]);
    if (from < 1 || to > 65535 || from > to) return null;
    return { from: from, to: to };
  }

  // 같은 프로토콜의 겹치거나 맞닿은 범위를 합친다.
  function merge(ranges) {
    var sorted = ranges.slice().sort(function (a, b) {
      if (a.proto !== b.proto) return a.proto < b.proto ? -1 : 1;
      return a.from - b.from;
    });
    var out = [];
    sorted.forEach(function (r) {
      var last = out[out.length - 1];
      if (last && last.proto === r.proto && r.from <= last.to + 1) {
        if (r.to > last.to) last.to = r.to;
      } else {
        out.push({ proto: r.proto, from: r.from, to: r.to });
      }
    });
    return out;
  }

  function parse(text) {
    if (typeof text !== 'string') return fail();
    var s = text.trim();
    if (/^any$/i.test(s)) return { ok: true, any: true, ranges: [] };
    if (!s) return fail();

    var tokens = s.split(',');
    var proto = null;
    var ranges = [];
    for (var i = 0; i < tokens.length; i++) {
      var t = tokens[i].trim();
      var m = /^(tcp|udp)\s+(.+)$/i.exec(t);
      var portText;
      if (m) {
        proto = m[1].toUpperCase();
        portText = m[2].trim();
      } else {
        if (!proto) return fail(); // 프로토콜 없이 시작하거나 빈 토큰
        portText = t;
      }
      var pr = parsePort(portText);
      if (!pr) return fail();
      ranges.push({ proto: proto, from: pr.from, to: pr.to });
    }
    return { ok: true, any: false, ranges: merge(ranges) };
  }

  // A 가 B 를 완전히 덮는가 (SPEC 2-3)
  function covers(a, b) {
    if (a.any) return true;
    if (b.any) return false;
    return b.ranges.every(function (br) {
      return a.ranges.some(function (ar) {
        return ar.proto === br.proto && ar.from <= br.from && br.to <= ar.to;
      });
    });
  }

  // 패킷(proto, port)이 서비스에 일치하는가
  function matches(svc, proto, port) {
    if (svc.any) return true;
    var p = String(proto).toUpperCase();
    return svc.ranges.some(function (r) {
      return r.proto === p && r.from <= port && port <= r.to;
    });
  }

  // 파싱 가능한 문자열로 되돌린다: "TCP 80,443, UDP 514"
  function format(svc) {
    if (svc.any) return 'Any';
    var groups = [];
    svc.ranges.forEach(function (r) {
      var g = groups[groups.length - 1];
      if (!g || g.proto !== r.proto) {
        g = { proto: r.proto, ports: [] };
        groups.push(g);
      }
      g.ports.push(r.from === r.to ? String(r.from) : r.from + '-' + r.to);
    });
    return groups.map(function (g) { return g.proto + ' ' + g.ports.join(','); }).join(', ');
  }

  var api = { ERR: ERR, parse: parse, covers: covers, matches: matches, format: format };

  root.PW = root.PW || {};
  root.PW.service = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
