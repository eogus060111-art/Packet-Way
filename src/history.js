/* history.js — 정책 변경 이력 (SPEC 2-5, 1-3-4)
 *
 * 항목: { time(ISO8601), type('add'|'edit'|'delete'|'move'), ruleNo, before, after, by }
 * 이력은 추가만 가능하다(수정·삭제 없음). all()/recent() 는 복사본을 돌려준다. */
(function (root) {
  'use strict';

  var TYPES = ['add', 'edit', 'delete', 'move'];
  var ERR_BY = '변경자를 입력하세요';

  function clone(v) { return v === undefined ? v : JSON.parse(JSON.stringify(v)); }

  function validBy(by) { return typeof by === 'string' && by.trim() !== ''; }

  function create(entries, now) {
    var list = (entries || []).map(clone);
    var clock = now || function () { return new Date().toISOString(); };

    return {
      // 한 건을 기록한다. 형식이 틀리면 기록하지 않고 { ok:false, error } 를 돌려준다.
      record: function (type, ruleNo, before, after, by) {
        if (TYPES.indexOf(type) === -1) return { ok: false, error: '변경 종류 오류' };
        if (!validBy(by)) return { ok: false, error: ERR_BY };
        var entry = {
          time: clock(),
          type: type,
          ruleNo: ruleNo,
          before: before === undefined ? null : clone(before),
          after: after === undefined ? null : clone(after),
          by: by.trim()
        };
        list.push(entry);
        return { ok: true, entry: clone(entry) };
      },
      all: function () { return list.map(clone); },                       // 오래된 순
      recent: function () { return list.map(clone).reverse(); },          // 최신 순 (화면 표시용)
      size: function () { return list.length; }
    };
  }

  var api = { TYPES: TYPES, ERR_BY: ERR_BY, create: create, validBy: validBy };

  root.PW = root.PW || {};
  root.PW.history = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
