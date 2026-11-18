# 패킷 길찾기 — 방화벽 정책 시뮬레이터

4구역(인터넷·DMZ·내부망·개발·운영 서버망) 방화벽 정책표에서 패킷이 어느 규칙에 걸려 허용·차단되는지 따라가 보고,
중복·섀도잉을 점검하고, 정책 변경 이력을 남기는 교육용 브라우저 앱이다.
판정 기준과 개념은 [SPEC.md](SPEC.md), 구현 계획은 [docs/PLAN.md](docs/PLAN.md) 에 있다.

## 실행

서버·설치·빌드가 필요 없다. `index.html` 을 브라우저로 열면 된다(더블클릭, `file://`).

- 정책표와 변경 이력은 브라우저 `localStorage` 에 저장된다. '정책표·이력 초기화' 버튼으로 기본 5행으로 되돌린다.
- 규칙을 바꾸려면 위쪽의 '변경자' 칸에 이름을 먼저 넣어야 한다(이력에 남기기 위해).

## 테스트

- 브라우저: `test/index.html` 을 열면 결과가 표시된다.
- Node 가 있으면: `node test/run-node.js`
- 새 모듈을 만들면 `test/index.html` 과 `test/run-node.js` 에 추가한다.

## 구조

```
index.html          앱 진입점 (일반 <script> 를 순서대로 로드)
css/style.css
src/
  topology.js       구역·호스트·주소 그룹·기본 정책표, IPv4/CIDR, IP→구역
  service.js        서비스 문자열 파싱·포함(covers)·일치
  address.js        주소 표현식 해석·포함(covers)·일치
  validator.js      규칙 입력 검증
  engine.js         first-match 패킷 판정
  analyzer.js       정책 점검(기본 거부·섀도잉·중복·syslog)
  history.js        변경 이력 (추가만 가능)
  policy.js         정책표 편집(추가·수정·삭제·이동) + 이력 연동
  ui.js             화면
test/               모듈별 테스트와 harness.js
```

`file://` 에서는 ES 모듈이 막히므로 각 파일은 전역 `PW` 이름공간에 등록하고, Node 에서는 `module.exports` 로도 내보낸다.

## SPEC 번호 ↔ 구현 ↔ 테스트

| SPEC | 내용 | 구현 | 테스트 |
|---|---|---|---|
| 1-1-1, 2-1 | first-match, 일치 규칙 없으면 암묵적 차단 | `engine.js` | `engine.test.js` |
| 1-1-2, 2-2 | 기본 거부 검사 | `analyzer.js` | `analyzer.test.js` |
| 1-2, 1-4-4 | 구간별 허용 정책표, 4구역 | `topology.js` | `topology.test.js`, `engine.test.js` |
| 1-2-6, 2-6 | syslog 표준 포트(UDP 514) 검사 | `analyzer.js` | `analyzer.test.js` |
| 1-3-1, 2-3 | 섀도잉 탐지, covers | `analyzer.js`, `address.js`, `service.js` | `analyzer.test.js`, `address.test.js`, `service.test.js` |
| 1-3-2, 2-4 | 중복 탐지 | `analyzer.js` | `analyzer.test.js` |
| 1-3-4, 2-5 | 변경 이력 항목·자동 기록 | `history.js`, `policy.js` | `history.test.js`, `policy.test.js` |
| 1-5-2 | '정책 점검' 버튼 | `ui.js` (+ `analyzer.js`) | UI 는 수동 확인 |
| 2-7 | 입력 검증("알 수 없는 주소", "서비스 형식 오류") | `validator.js`, `address.js`, `service.js` | `validator.test.js` 외 |
| 3-1 | 함정 1: 1번이 Any→Any 허용이면 아래 차단 규칙 전부 섀도잉 | `analyzer.js` | `analyzer.test.js` "T1" |
| 3-2 | 함정 2: 개발 서버(10.20.1.20) → 인터넷(203.0.113.10) TCP 443 은 5번에서 차단 | `engine.js` | `engine.test.js` "T2", 화면 프리셋 |
| 3-3 | 함정 3: syslog UDP 513 경고, 514 경고 없음 | `analyzer.js` | `analyzer.test.js` "T3" |

## SPEC 이 정하지 않아 구현에서 정한 것

- 섀도잉·중복은 위 규칙 i 와 아래 규칙 j 의 모든 쌍마다 보고한다(같은 규칙을 여러 규칙이 가리면 경고가 여러 개).
- syslog 검사는 로그 수집 규칙에 UDP 포트가 하나라도 있는데 514 가 없을 때만 경고한다. UDP 없이 TCP 9200 만 있으면 경고하지 않는다.
- 규칙 이동 이력의 `ruleNo` 는 이동 전 번호이고, 이동 후 번호는 `after.no` 에 남는다.
- 동작 값이 `allow`/`deny` 가 아니면 "동작 오류" 로 거부한다. 패킷 입력(IP·프로토콜·포트) 오류에는 SPEC 2-7 의 문구를 그대로 쓴다.
- 규칙 추가 위치를 정하지 않으면 맨 아래(기본 거부 규칙 아래)에 붙는다. 위치(번호)를 넣어 끼워 넣을 수 있다.
- IP 대역과 호스트·주소 그룹은 docs/PLAN.md 1절의 제안값이다. SPEC 에서 확정된 값은 10.20.1.20(개발 서버)과 203.0.113.10(외부 예시)뿐이다.
