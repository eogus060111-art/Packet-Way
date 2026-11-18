/* topology.js 테스트 (PLAN 8절, 마일스톤 1) */
(function (root) {
  'use strict';
  var T = root.PWTest || require('./harness.js');
  var topo = root.PW ? root.PW.topology : require('../src/topology.js');
  var test = T.test, eq = T.eq, ok = T.ok;

  test('구역은 4개이고 이름이 SPEC 1-4-4 와 같다', function () {
    eq(topo.zones.map(function (z) { return z.name; }), ['인터넷', 'DMZ', '내부망', '개발·운영 서버망']);
  });

  test('IP 가 구역 CIDR 에 정확히 한 구역으로 판정된다', function () {
    eq(topo.zoneOf('172.16.10.10'), 'DMZ');
    eq(topo.zoneOf('192.168.10.50'), '내부망');
    eq(topo.zoneOf('10.20.1.20'), '개발·운영 서버망');
  });

  test('사설 구역에 없으면 인터넷', function () {
    eq(topo.zoneOf('203.0.113.10'), '인터넷');
    eq(topo.zoneOf('8.8.8.8'), '인터넷');
    eq(topo.zoneOf('172.16.11.1'), '인터넷', 'DMZ /24 바로 바깥');
  });

  test('CIDR 경계', function () {
    ok(topo.inCidr('10.20.1.0', '10.20.1.0/24'));
    ok(topo.inCidr('10.20.1.255', '10.20.1.0/24'));
    ok(!topo.inCidr('10.20.2.0', '10.20.1.0/24'));
  });

  test('모든 호스트는 자기 구역에 속한다', function () {
    eq(topo.zoneOf(topo.findHost('웹서버').ip), 'DMZ');
    eq(topo.zoneOf(topo.findHost('DB 서버').ip), '내부망');
    eq(topo.zoneOf(topo.findHost('운영 서버').ip), '개발·운영 서버망');
    eq(topo.zoneOf(topo.findHost('외부 사용자(예시)').ip), '인터넷');
  });

  test('올바르지 않은 IPv4 는 거부', function () {
    ['300.1.1.1', '1.2.3', '1.2.3.4.5', 'abc', '', '1.2.3.-4'].forEach(function (s) {
      ok(!topo.isValidIPv4(s), s);
    });
    eq(topo.zoneOf('300.1.1.1'), null);
  });

  test('구역 CIDR 끼리 겹치지 않는다', function () {
    var rs = topo.zones.filter(function (z) { return z.cidr; })
      .map(function (z) { return topo.cidrRange(z.cidr); });
    for (var i = 0; i < rs.length; i++) for (var j = i + 1; j < rs.length; j++) {
      ok(rs[i].end < rs[j].start || rs[j].end < rs[i].start, '겹침 ' + i + ',' + j);
    }
  });

  test('주소 그룹의 호스트 참조는 모두 존재한다', function () {
    topo.groups.forEach(function (g) {
      g.members.forEach(function (m) {
        if (m.host) ok(topo.findHost(m.host), g.name + ' → ' + m.host);
        if (m.zone) ok(topo.isZoneName(m.zone), g.name + ' → ' + m.zone);
      });
    });
  });

  test('기본 정책표는 5행이고 마지막은 Any-Any-Any 차단', function () {
    var p = topo.defaultPolicy();
    eq(p.length, 5);
    eq(p.map(function (r) { return r.no; }), [1, 2, 3, 4, 5]);
    var last = p[4];
    eq([last.src, last.dst, last.service, last.action], ['Any', 'Any', 'Any', 'deny']);
  });

  test('기본 정책표의 주소는 모두 Any/그룹/구역 이름이다', function () {
    topo.defaultPolicy().forEach(function (r) {
      [r.src, r.dst].forEach(function (a) {
        ok(a === 'Any' || topo.findGroup(a) || topo.isZoneName(a), a);
      });
    });
  });

  test('defaultPolicy 는 호출마다 새 배열을 돌려준다(원본 보호)', function () {
    var a = topo.defaultPolicy(); a[0].action = 'deny';
    eq(topo.defaultPolicy()[0].action, 'allow');
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
