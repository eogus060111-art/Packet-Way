/* topology.js — 4구역 토폴로지, 호스트, 주소 그룹, 기본 정책표 (PLAN 1절, SPEC 1-2·1-4-4·2 서두)
 * 브라우저(file://)와 Node 양쪽에서 쓰도록 전역 PW 이름공간에 등록한다. */
(function (root) {
  'use strict';

  var INTERNET = '인터넷';

  // 구역: 인터넷은 CIDR 이 없는 보충 구역 (사설 세 구역에 속하지 않는 모든 IP)
  var zones = [
    { name: INTERNET, cidr: null, desc: '신뢰할 수 없는 외부' },
    { name: 'DMZ', cidr: '172.16.10.0/24', desc: '외부 공개 서버 완충 구역(웹·메일)' },
    { name: '내부망', cidr: '192.168.10.0/24', desc: '업무 PC, DB, 인증, SIEM' },
    { name: '개발·운영 서버망', cidr: '10.20.1.0/24', desc: '운영 서버, 개발 서버' }
  ];

  var hosts = [
    { name: '웹서버', ip: '172.16.10.10' },
    { name: '메일서버', ip: '172.16.10.20' },
    { name: '업무 PC', ip: '192.168.10.100' },
    { name: '관리자 PC', ip: '192.168.10.5' },
    { name: 'DB 서버', ip: '192.168.10.30' },
    { name: '인증 서버', ip: '192.168.10.40' },
    { name: 'SIEM', ip: '192.168.10.50' },
    { name: '운영 서버', ip: '10.20.1.10' },
    { name: '개발 서버', ip: '10.20.1.20' },
    { name: '외부 사용자(예시)', ip: '203.0.113.10' }
  ];

  // 주소 그룹: members 는 { zone } 또는 { host } (호스트 이름) 로 이루어진다.
  var groups = [
    { name: '외부망', members: [{ zone: INTERNET }] },
    { name: 'DMZ 웹서버', members: [{ host: '웹서버' }] },
    { name: '내부망 DB 서버', members: [{ host: 'DB 서버' }] },
    { name: '내부망 관리자 PC', members: [{ host: '관리자 PC' }] },
    { name: '개발·운영 서버', members: [{ host: '운영 서버' }, { host: '개발 서버' }] },
    { name: '내부 장비·DMZ', members: [
      { host: '업무 PC' }, { host: '관리자 PC' }, { host: 'DB 서버' },
      { host: '인증 서버' }, { host: 'SIEM' },
      { host: '웹서버' }, { host: '메일서버' }
    ] },
    { name: '보안관제(SIEM)', members: [{ host: 'SIEM' }] }
  ];

  // 기본 정책표 5행 (SPEC 1-2). service 는 문자열 그대로 두고 service.js 가 해석한다.
  function defaultPolicy() {
    return [
      { no: 1, src: '외부망', dst: 'DMZ 웹서버', service: 'TCP 80,443', action: 'allow', purpose: '외부 사용자 서비스 제공' },
      { no: 2, src: 'DMZ 웹서버', dst: '내부망 DB 서버', service: 'TCP 1433,3306', action: 'allow', purpose: '웹서비스용 DB 연동(지정 IP 한정)' },
      { no: 3, src: '내부망 관리자 PC', dst: '개발·운영 서버', service: 'TCP 22', action: 'allow', purpose: '내부 특정 IP만 관리 접근' },
      { no: 4, src: '내부 장비·DMZ', dst: '보안관제(SIEM)', service: 'UDP 514,TCP 9200', action: 'allow', purpose: '로그 중앙 수집' },
      { no: 5, src: 'Any', dst: 'Any', service: 'Any', action: 'deny', purpose: '미허용·역방향 트래픽 전면 차단' }
    ];
  }

  // ---- IPv4 / CIDR 도우미 ----

  // 올바른 IPv4 문자열이면 부호 없는 32비트 정수, 아니면 null
  function ipToInt(ip) {
    if (typeof ip !== 'string') return null;
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
    if (!m) return null;
    var n = 0;
    for (var i = 1; i <= 4; i++) {
      var o = Number(m[i]);
      if (o > 255) return null;
      n = n * 256 + o;
    }
    return n;
  }

  function isValidIPv4(ip) { return ipToInt(ip) !== null; }

  // "a.b.c.d/n" → { start, end } (둘 다 포함), 잘못되면 null
  function cidrRange(cidr) {
    var m = /^([^/]+)\/(\d{1,2})$/.exec(cidr);
    if (!m) return null;
    var base = ipToInt(m[1]);
    var bits = Number(m[2]);
    if (base === null || bits > 32) return null;
    var size = Math.pow(2, 32 - bits);
    var start = Math.floor(base / size) * size;
    return { start: start, end: start + size - 1 };
  }

  function inCidr(ip, cidr) {
    var n = ipToInt(ip);
    var r = cidrRange(cidr);
    return n !== null && r !== null && n >= r.start && n <= r.end;
  }

  // IP → 구역 이름. 세 사설 구역에 없으면 '인터넷'. 잘못된 IP 는 null.
  function zoneOf(ip) {
    if (!isValidIPv4(ip)) return null;
    for (var i = 0; i < zones.length; i++) {
      if (zones[i].cidr && inCidr(ip, zones[i].cidr)) return zones[i].name;
    }
    return INTERNET;
  }

  function findHost(name) {
    for (var i = 0; i < hosts.length; i++) if (hosts[i].name === name) return hosts[i];
    return null;
  }

  function findGroup(name) {
    for (var i = 0; i < groups.length; i++) if (groups[i].name === name) return groups[i];
    return null;
  }

  function isZoneName(name) {
    for (var i = 0; i < zones.length; i++) if (zones[i].name === name) return true;
    return false;
  }

  var api = {
    INTERNET: INTERNET,
    zones: zones,
    hosts: hosts,
    groups: groups,
    defaultPolicy: defaultPolicy,
    ipToInt: ipToInt,
    isValidIPv4: isValidIPv4,
    cidrRange: cidrRange,
    inCidr: inCidr,
    zoneOf: zoneOf,
    findHost: findHost,
    findGroup: findGroup,
    isZoneName: isZoneName
  };

  root.PW = root.PW || {};
  root.PW.topology = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
