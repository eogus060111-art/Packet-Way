/* harness.js — 아주 작은 테스트 도구. 브라우저(test/index.html)와 Node 양쪽에서 동작한다.
 * 사용: PWTest.test('이름', function () { PWTest.eq(실제, 기대); }); */
(function (root) {
  'use strict';

  var tests = [];

  function test(name, fn) { tests.push({ name: name, fn: fn }); }

  function fail(msg) { throw new Error(msg); }

  function eq(actual, expected, label) {
    var a = JSON.stringify(actual), e = JSON.stringify(expected);
    if (a !== e) fail((label ? label + ': ' : '') + '기대 ' + e + ' 인데 ' + a);
  }

  function ok(cond, label) { if (!cond) fail(label || '조건이 거짓'); }

  function run() {
    var results = tests.map(function (t) {
      try { t.fn(); return { name: t.name, pass: true }; }
      catch (e) { return { name: t.name, pass: false, error: e.message }; }
    });
    return results;
  }

  function report(results) {
    var failed = results.filter(function (r) { return !r.pass; });
    if (typeof document !== 'undefined') {
      var out = document.getElementById('result');
      var html = '<p><b>' + (results.length - failed.length) + ' / ' + results.length + ' 통과</b></p><ul>';
      results.forEach(function (r) {
        html += '<li style="color:' + (r.pass ? 'green' : 'red') + '">' + (r.pass ? '✔ ' : '✘ ') +
          r.name + (r.pass ? '' : ' — ' + r.error) + '</li>';
      });
      out.innerHTML = html + '</ul>';
    } else {
      results.forEach(function (r) {
        console.log((r.pass ? 'ok   ' : 'FAIL ') + r.name + (r.pass ? '' : ' — ' + r.error));
      });
      console.log(results.length - failed.length + '/' + results.length + ' passed');
      if (failed.length) process.exitCode = 1;
    }
  }

  var api = { test: test, eq: eq, ok: ok, run: run, report: report };
  root.PWTest = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
