"use strict";
const assert = require("node:assert/strict");
const { rocAuc, pointsAtResolvableFpr, zeroFpPoint, clustersAll, distanceMatrix, makeScores } = require("../tools/eval_kit.js");

assert.equal(rocAuc([0.9, 0.1], [1, 0]), 1);
assert.equal(rocAuc([0.5, 0.5], [1, 0]), 0.5);
const scores = [0, 2, 5, 8];
const labels = [0, 1, 0, 1];
assert.equal(zeroFpPoint(scores, labels).tp, 1);
assert.equal(zeroFpPoint(scores, labels).fp, 0);
assert.equal(pointsAtResolvableFpr(scores, labels)[0].fp, 0);

const pages = [
  { fp: "0000000000000000", label: 1 },
  { fp: "0000000000000001", label: 1 },
  { fp: "000000000000000f", label: 0 },
  { fp: "ffffffffffffffff", label: 0 }
];
const distances = distanceMatrix(pages);
assert.deepEqual(clustersAll(pages, distances, 1).map((cluster) => cluster.length).sort(), [1, 1, 2]);
const nearest = makeScores(pages, distances);
assert.equal(nearest.length, pages.length);
assert.ok(nearest.every((item) => Number.isFinite(item.score)));

console.log("Offline kit evaluation metric tests passed.");
