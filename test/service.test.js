/* service.js 테스트 (PLAN 8절: 서비스 형식, covers 경계) */
(function (root) {
  'use strict';
  var T = root.PWTest || require('./harness.js');
  var svc = root.PW ? root.PW.service : require('../src/service.js');
  var test = T.test, eq = T.eq, ok = T.ok;

  function p(s) { return svc.parse(s); }

  test('Any 는 대소문자 무관하게 파싱된다', function () {
    ok(p('Any').ok && p('Any').any);
    ok(p(' any ').any);
  });

  test('TCP 80,443 → 두 포트', function () {
    eq(p('TCP 80,443').ranges, [{ proto: 'TCP', from: 80, to: 80 }, { proto: 'TCP', from: 443, to: 443 }]);
  });

  test('UDP 514,TCP 9200 → 프로토콜이 바뀌어도 한 문자열로 파싱', function () {
    var r = p('UDP 514,TCP 9200');
    ok(r.ok);
    ok(svc.matches(r, 'UDP', 514));
    ok(svc.matches(r, 'TCP', 9200));
    ok(!svc.matches(r, 'TCP', 514));
    ok(!svc.matches(r, 'UDP', 9200));
  });

  test('소문자·공백 허용, 포트 범위 허용', function () {
    var r = p('tcp 80 , 443, udp 1000-2000');
    ok(r.ok);
    ok(svc.matches(r, 'UDP', 1500));
    ok(!svc.matches(r, 'UDP', 2001));
  });

  test('서비스 형식 오류', function () {
    ['', '   ', 'TCP', 'TCP 99999', 'TCP 0', '80', 'TCP80', 'ICMP 1', 'TCP 80,,443',
      'TCP 80,', 'Any, TCP 80', 'TCP Any', 'TCP 90-80', 'TCP 80 443', 'TCP -1', 'TCP abc'
    ].forEach(function (s) {
      var r = p(s);
      ok(!r.ok, '"' + s + '" 는 오류여야 함');
      eq(r.error, '서비스 형식 오류');
    });
    ok(!svc.parse(null).ok);
    ok(!svc.parse(undefined).ok);
  });

  test('범위 병합: 80,81,82 → 80-82', function () {
    eq(p('TCP 80,81,82').ranges, [{ proto: 'TCP', from: 80, to: 82 }]);
    eq(p('TCP 100-200,150-300').ranges, [{ proto: 'TCP', from: 100, to: 300 }]);
  });

  test('covers: Any 와 비-Any', function () {
    ok(svc.covers(p('Any'), p('TCP 80')));
    ok(svc.covers(p('Any'), p('Any')));
    ok(!svc.covers(p('TCP 80'), p('Any')));
  });

  test('covers: 포트 부분 포함', function () {
    ok(svc.covers(p('TCP 80,443'), p('TCP 80')));
    ok(svc.covers(p('TCP 80,443'), p('TCP 443,80')));
    ok(!svc.covers(p('TCP 80'), p('TCP 80,443')));
    ok(!svc.covers(p('TCP 80,443'), p('TCP 80,8080')));
  });

  test('covers: 프로토콜이 다르면 덮지 못한다', function () {
    ok(!svc.covers(p('TCP 514'), p('UDP 514')));
    ok(svc.covers(p('UDP 514,TCP 9200'), p('UDP 514')));
    ok(!svc.covers(p('UDP 514,TCP 9200'), p('UDP 513')));
  });

  test('covers: 범위가 이어 붙은 경우(병합 후) 포함', function () {
    ok(svc.covers(p('TCP 80-100,101-200'), p('TCP 90-150')));
    ok(!svc.covers(p('TCP 80-100,102-200'), p('TCP 90-150')));
  });

  test('matches: Any 는 모든 패킷, 프로토콜 대소문자 무관', function () {
    ok(svc.matches(p('Any'), 'TCP', 1));
    ok(svc.matches(p('TCP 80'), 'tcp', 80));
    ok(!svc.matches(p('TCP 80'), 'TCP', 81));
  });

  test('format 은 다시 파싱하면 같은 결과', function () {
    ['Any', 'TCP 80,443', 'UDP 514,TCP 9200', 'TCP 1000-2000,22'].forEach(function (s) {
      var a = p(s);
      eq(p(svc.format(a)), a, s);
    });
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
