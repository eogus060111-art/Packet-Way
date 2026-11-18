/* engine.js — 패킷 판정 = first-match (SPEC 2-1, 1-1-1)
 *
 * 규칙을 번호 오름차순으로 비교해 출발지·목적지·프로토콜·포트가 모두 일치하는 '첫 규칙'의
 * 동작을 결과로 하고 즉시 멈춘다. 일치 규칙이 없으면 암묵적 차단(matched=null, deny)과
 * 경고를 돌려준다.
 *
 * judge(rules, packet) → 성공: { ok:true, action, matched, srcZone, dstZone, warnings, trace }
 *                        실패: { ok:false, errors:[{ field, message }] }  (패킷 입력 오류)
 *   packet = { srcIp, dstIp, proto:'TCP'|'UDP', port:정수 }
 *   trace  = 비교한 규칙들 [{ no, action, matched, mismatch:['출발지'|'목적지'|'서비스'] }]
 *            (일치한 규칙이 마지막이고, 그 아래 규칙은 비교하지 않으므로 trace 에도 없다) */
(function (root) {
  'use strict';

  var topo = (root.PW && root.PW.topology) || require('./topology.js');
  var address = (root.PW && root.PW.address) || require('./address.js');
  var service = (root.PW && root.PW.service) || require('./service.js');

  var NO_MATCH_WARNING = '일치 규칙 없음 — 기본 거부 규칙 필요';

  function checkPacket(p) {
    var errors = [];
    if (!p || !topo.isValidIPv4(p.srcIp)) errors.push({ field: 'srcIp', message: address.ERR });
    if (!p || !topo.isValidIPv4(p.dstIp)) errors.push({ field: 'dstIp', message: address.ERR });
    var proto = p && typeof p.proto === 'string' ? p.proto.toUpperCase() : '';
    if (proto !== 'TCP' && proto !== 'UDP') errors.push({ field: 'proto', message: service.ERR });
    if (!p || !Number.isInteger(p.port) || p.port < 1 || p.port > 65535) {
      errors.push({ field: 'port', message: service.ERR });
    }
    return errors;
  }

  // 규칙 하나를 패킷과 비교한다. 해석할 수 없는 규칙은 어느 항목도 일치하지 않는 것으로 본다.
  function compare(rule, packet, proto) {
    var s = address.resolve(rule.src);
    var d = address.resolve(rule.dst);
    var v = service.parse(rule.service);
    var mismatch = [];
    if (!s.ok || !address.matches(s, packet.srcIp)) mismatch.push('출발지');
    if (!d.ok || !address.matches(d, packet.dstIp)) mismatch.push('목적지');
    if (!v.ok || !service.matches(v, proto, packet.port)) mismatch.push('서비스');
    return mismatch;
  }

  function judge(rules, packet) {
    var errors = checkPacket(packet);
    if (errors.length) return { ok: false, errors: errors };

    var proto = packet.proto.toUpperCase();
    // 번호 오름차순(위→아래). 원본 배열은 건드리지 않는다.
    var ordered = rules.slice().sort(function (a, b) { return a.no - b.no; });
    var trace = [];

    for (var i = 0; i < ordered.length; i++) {
      var rule = ordered[i];
      var mismatch = compare(rule, packet, proto);
      var hit = mismatch.length === 0;
      trace.push({ no: rule.no, action: rule.action, matched: hit, mismatch: mismatch });
      if (hit) {
        return {
          ok: true,
          action: rule.action,
          matched: rule.no,
          srcZone: topo.zoneOf(packet.srcIp),
          dstZone: topo.zoneOf(packet.dstIp),
          warnings: [],
          trace: trace
        };
      }
    }

    return {
      ok: true,
      action: 'deny',
      matched: null,
      srcZone: topo.zoneOf(packet.srcIp),
      dstZone: topo.zoneOf(packet.dstIp),
      warnings: [NO_MATCH_WARNING],
      trace: trace
    };
  }

  var api = { NO_MATCH_WARNING: NO_MATCH_WARNING, judge: judge };

  root.PW = root.PW || {};
  root.PW.engine = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
