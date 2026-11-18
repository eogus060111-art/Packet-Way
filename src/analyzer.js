/* analyzer.js — 정책 점검 (SPEC 2-2 기본 거부, 2-3 섀도잉, 2-4 중복, 2-6 syslog 표준 포트)
 *
 * analyze(rules) → { warnings:[{ type, ruleNo, relatedNo, message }] }
 *   type: 'default-deny' | 'shadowing' | 'redundancy' | 'syslog'
 *   ruleNo: 경고가 붙는 규칙 번호 (기본 거부 경고는 null), relatedNo: 가리는 위쪽 규칙 번호
 * 경고 순서: 기본 거부 → 섀도잉·중복(아래 규칙 번호 순) → syslog (규칙 번호 순)
 * 형식 오류가 있어 해석할 수 없는 규칙은 점검에서 제외한다(validator 가 따로 보고). */
(function (root) {
  'use strict';

  var topo = (root.PW && root.PW.topology) || require('./topology.js');
  var address = (root.PW && root.PW.address) || require('./address.js');
  var service = (root.PW && root.PW.service) || require('./service.js');

  var MSG_NO_DEFAULT_DENY = '마지막 Any-Any 차단(기본 거부) 규칙이 없습니다';
  var SYSLOG_PORT = 514;

  function msgShadowing(j, i) {
    return '규칙 ' + j + ' 는 규칙 ' + i + ' 에 가려져 절대 적용되지 않습니다(섀도잉)';
  }
  function msgRedundancy(j, i) {
    return '규칙 ' + j + ' 는 규칙 ' + i + ' 와 중복입니다(같은 트래픽·같은 동작)';
  }
  function msgSyslog(n) {
    return '규칙 ' + n + ': syslog 표준 포트가 아님 (UDP 513 → 표준 포트는 UDP 514)';
  }

  function parseRule(rule) {
    return {
      rule: rule,
      s: address.resolve(rule.src),
      d: address.resolve(rule.dst),
      v: service.parse(rule.service)
    };
  }

  function usable(p) { return p.s.ok && p.d.ok && p.v.ok; }

  // 출발지·목적지·서비스 Any 이고 동작이 차단
  function isDefaultDeny(p) {
    return usable(p) && p.s.any && p.d.any && p.v.any && p.rule.action === 'deny';
  }

  // 위 규칙 i 가 아래 규칙 j 의 출발지·목적지·서비스를 각각 완전히 덮는가
  function fullyCovers(i, j) {
    return address.covers(i.s, j.s) && address.covers(i.d, j.d) && service.covers(i.v, j.v);
  }

  // 로그 수집 규칙 (SPEC 2-6): 목적지가 '보안관제(SIEM)' 그룹이거나 SIEM 호스트 IP,
  // 또는 목적에 'syslog'/'로그' 가 들어 있다.
  function isLogRule(rule) {
    var dst = String(rule.dst).trim();
    if (dst === '보안관제(SIEM)') return true;
    var siem = topo.findHost('SIEM');
    var n = topo.ipToInt(dst);
    if (siem && n !== null && n === topo.ipToInt(siem.ip)) return true;
    return /syslog|로그/i.test(String(rule.purpose || ''));
  }

  // UDP 포트를 지정했는데 514 가 하나도 없으면 참. 서비스가 Any 이거나 UDP 를 아예 쓰지 않으면 거짓.
  function lacksStandardSyslogPort(v) {
    if (v.any) return false;
    var udp = v.ranges.filter(function (r) { return r.proto === 'UDP'; });
    if (udp.length === 0) return false;
    return !udp.some(function (r) { return r.from <= SYSLOG_PORT && SYSLOG_PORT <= r.to; });
  }

  function analyze(rules) {
    var parsed = rules.slice().sort(function (a, b) { return a.no - b.no; }).map(parseRule);
    var warnings = [];

    // 2-2 기본 거부 검사: 마지막 규칙이 Any-Any-Any 차단이어야 한다
    var last = parsed[parsed.length - 1];
    if (!last || !isDefaultDeny(last)) {
      warnings.push({ type: 'default-deny', ruleNo: null, relatedNo: null, message: MSG_NO_DEFAULT_DENY });
    }

    // 2-3 섀도잉 / 2-4 중복: 위 규칙 i 가 아래 규칙 j 를 완전히 덮을 때
    //   동작이 다르면 섀도잉, 같으면 중복. 한 쌍(i, j)은 둘 중 하나로만 보고한다.
    for (var j = 1; j < parsed.length; j++) {
      if (!usable(parsed[j])) continue;
      for (var i = 0; i < j; i++) {
        if (!usable(parsed[i]) || !fullyCovers(parsed[i], parsed[j])) continue;
        var ni = parsed[i].rule.no, nj = parsed[j].rule.no;
        if (parsed[i].rule.action !== parsed[j].rule.action) {
          warnings.push({ type: 'shadowing', ruleNo: nj, relatedNo: ni, message: msgShadowing(nj, ni) });
        } else {
          warnings.push({ type: 'redundancy', ruleNo: nj, relatedNo: ni, message: msgRedundancy(nj, ni) });
        }
      }
    }

    // 2-6 syslog 표준 포트 검사
    parsed.forEach(function (p) {
      if (usable(p) && isLogRule(p.rule) && lacksStandardSyslogPort(p.v)) {
        warnings.push({ type: 'syslog', ruleNo: p.rule.no, relatedNo: null, message: msgSyslog(p.rule.no) });
      }
    });

    return { warnings: warnings };
  }

  var api = {
    MSG_NO_DEFAULT_DENY: MSG_NO_DEFAULT_DENY,
    analyze: analyze,
    isLogRule: isLogRule
  };

  root.PW = root.PW || {};
  root.PW.analyzer = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
