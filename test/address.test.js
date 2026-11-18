/* address.js 테스트 (PLAN 8절: covers 경계 — Any vs 비-Any, 구역 vs 단일 IP) */
(function (root) {
  'use strict';
  var T = root.PWTest || require('./harness.js');
  var addr = root.PW ? root.PW.address : require('../src/address.js');
  var test = T.test, eq = T.eq, ok = T.ok;

  function r(s) { return addr.resolve(s); }
  function covers(a, b) { return addr.covers(r(a), r(b)); }

  test('Any·구역·그룹·IP 를 해석한다', function () {
    ok(r('Any').ok && r('Any').any);
    eq(r('DMZ').zones, ['DMZ']);
    eq(r('외부망').zones, ['인터넷']);
    ok(r('DMZ 웹서버').ok);
    ok(r('10.20.1.20').ok);
    ok(r(' 10.20.1.20 ').ok, '앞뒤 공백 허용');
  });

  test('알 수 없는 주소는 오류 문구', function () {
    ['', '없는그룹', '300.1.1.1', '1.2.3', 'DMZ,내부망'].forEach(function (s) {
      var x = r(s);
      ok(!x.ok, '"' + s + '" 는 오류여야 함');
      eq(x.error, '알 수 없는 주소');
    });
    ok(!addr.resolve(null).ok);
  });

  test('covers: Any', function () {
    ok(covers('Any', 'DMZ'));
    ok(covers('Any', 'Any'));
    ok(!covers('DMZ', 'Any'));
    ok(!covers('외부망', 'Any'));
  });

  test('covers: 구역이 단일 IP·그룹을 덮는다', function () {
    ok(covers('내부망', '내부망 DB 서버'));
    ok(covers('내부망', '192.168.10.30'));
    ok(covers('개발·운영 서버망', '개발·운영 서버'));
  });

  test('covers: 단일 IP·그룹은 구역 전체를 덮지 못한다', function () {
    ok(!covers('내부망 DB 서버', '내부망'));
    ok(!covers('192.168.10.30', '내부망'));
    ok(!covers('개발·운영 서버', '개발·운영 서버망'));
  });

  test('covers: 그룹이 그 구성 IP 를 덮고 다른 IP 는 덮지 못한다', function () {
    ok(covers('개발·운영 서버', '10.20.1.20'));
    ok(!covers('개발·운영 서버', '10.20.1.30'));
    ok(covers('내부 장비·DMZ', '보안관제(SIEM)'));
    ok(!covers('보안관제(SIEM)', '내부 장비·DMZ'));
  });

  test('covers: 서로 다른 구역은 덮지 못한다', function () {
    ok(!covers('DMZ', '내부망'));
    ok(!covers('외부망', 'DMZ'));
    ok(!covers('DMZ', '외부망'));
    ok(covers('외부망', '203.0.113.10'));
    ok(!covers('외부망', '172.16.10.10'));
  });

  test('covers: 같은 표현은 서로를 덮는다', function () {
    ['DMZ', '내부망 DB 서버', '10.20.1.20', '외부망'].forEach(function (s) {
      ok(covers(s, s), s);
    });
  });

  test('matches: 패킷 IP 가 주소에 속하는가', function () {
    ok(addr.matches(r('Any'), '8.8.8.8'));
    ok(addr.matches(r('외부망'), '203.0.113.10'));
    ok(!addr.matches(r('외부망'), '172.16.10.10'));
    ok(addr.matches(r('DMZ 웹서버'), '172.16.10.10'));
    ok(!addr.matches(r('DMZ 웹서버'), '172.16.10.20'), '같은 DMZ 라도 웹서버 IP 가 아님');
    ok(addr.matches(r('DMZ'), '172.16.10.20'));
    ok(addr.matches(r('개발·운영 서버'), '10.20.1.20'));
    ok(!addr.matches(r('개발·운영 서버'), '10.20.1.99'));
    ok(!addr.matches(r('DMZ'), 'abc'), '잘못된 IP 는 일치하지 않음');
  });

  test('intToIp 는 ipToInt 의 역함수', function () {
    var topo = root.PW ? root.PW.topology : require('../src/topology.js');
    ['0.0.0.0', '10.20.1.20', '192.168.10.5', '255.255.255.255'].forEach(function (ip) {
      eq(addr.intToIp(topo.ipToInt(ip)), ip);
    });
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
