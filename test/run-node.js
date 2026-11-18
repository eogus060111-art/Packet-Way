// Node 가 있을 때만 쓰는 실행기: node test/run-node.js
// 브라우저만 쓴다면 test/index.html 을 열면 된다.
const T = require('./harness.js');
require('./topology.test.js');
require('./service.test.js');
require('./address.test.js');
require('./validator.test.js');
require('./engine.test.js');
require('./analyzer.test.js');
require('./history.test.js');
require('./policy.test.js');
T.report(T.run());
